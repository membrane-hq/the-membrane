//! Separate, unprivileged audit consumer and approval relay. The dashboard keeps no
//! keys, token, or connector of its own: approval list and decision calls forward the
//! operator's per-request OIDC bearer token to the gate, which authenticates the
//! operator and publishes the signed decision receipt. Nothing is stored here.
use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json,
};
use clap::Parser;
use membrane_gate::audit::{local_only, loopback_address, Snapshot};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;

const MAX_UPSTREAM_BODY: usize = 2_000_000;
const MAX_NOTE_BYTES: usize = 1024;

#[derive(Parser)]
#[command(about = "Local Membrane operator dashboard: audit telemetry and approval decisions")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8790")]
    listen: String,
    #[arg(long, default_value = "http://127.0.0.1:8788")]
    audit_url: String,
    /// Loopback base URL of the production gate router, used for approval decisions.
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    gate_url: String,
}
#[derive(Clone)]
struct App {
    client: reqwest::Client,
    audit: String,
    approvals: String,
}
/// A plain loopback HTTP base URL: no credentials, query, fragment or path.
fn loopback_base(input: &str) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(input)?;
    anyhow::ensure!(
        url.scheme() == "http"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "use a plain loopback HTTP base URL"
    );
    let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
    let ip: std::net::IpAddr = host.parse()?;
    anyhow::ensure!(ip.is_loopback(), "upstream must be a literal loopback IP");
    Ok(url)
}
fn audit_url(input: &str) -> anyhow::Result<String> {
    Ok(loopback_base(input)?.join("audit")?.to_string())
}
fn approvals_url(input: &str) -> anyhow::Result<String> {
    Ok(loopback_base(input)?.join("/v1/approvals")?.to_string())
}
/// Read a bounded upstream body; over the cap is an error, never a truncation.
async fn bounded_body(response: reqwest::Response) -> anyhow::Result<(StatusCode, Vec<u8>)> {
    if response
        .content_length()
        .is_some_and(|n| n > MAX_UPSTREAM_BODY as u64)
    {
        anyhow::bail!("gate response too large");
    }
    let status = response.status();
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(
            bytes.len() + chunk.len() <= MAX_UPSTREAM_BODY,
            "gate response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}
async fn data(State(app): State<App>) -> Response {
    // Redirects disabled; timeout and size bound; never forwards browser cookies/headers.
    let result = async {
        let response = app
            .client
            .get(&app.audit)
            .send()
            .await?
            .error_for_status()?;
        let (_, bytes) = bounded_body(response).await?;
        let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            snapshot.schema_version == 1 && snapshot.audit_available,
            "unsupported or unavailable audit snapshot"
        );
        Ok::<_, anyhow::Error>(snapshot)
    }
    .await;
    match result {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"unknown", "error":"Audit source unavailable. Gate status is not verified."})),
        )
            .into_response(),
    }
}
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|t| !t.is_empty())
}
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"ok": false, "message": "operator bearer token required"})),
    )
        .into_response()
}
/// Pass the gate's status and JSON body back, or 502 when the gate cannot be read.
async fn relay(response: Result<reqwest::Response, reqwest::Error>) -> Response {
    let response = match response {
        Ok(response) => response,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "message": "gate unreachable"})),
            )
                .into_response()
        }
    };
    match bounded_body(response).await {
        Ok((status, bytes)) => {
            (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "message": "gate response unreadable"})),
        )
            .into_response(),
    }
}
/// Operator holds, relayed from the gate with the operator's own token.
async fn approvals_list(State(app): State<App>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return unauthorized();
    };
    relay(
        app.client
            .get(&app.approvals)
            .bearer_auth(token)
            .send()
            .await,
    )
    .await
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionBody {
    decision: String,
    #[serde(default)]
    note: Option<String>,
}
/// Approval ids are gate-generated lowercase hex; anything else is not a hold.
fn valid_approval_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// One operator decision, relayed to the gate. The gate authenticates the token,
/// publishes the signed decision receipt, then applies the decision.
async fn approvals_decide(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<DecisionBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return unauthorized();
    };
    if !valid_approval_id(&id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "message": "unknown approval id format"})),
        )
            .into_response();
    }
    let Json(body) =
        match body {
            Ok(body) => body,
            Err(_) => return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "message": "body must be JSON: decision, optional note"})),
            )
                .into_response(),
        };
    if body.decision != "approve" && body.decision != "reject" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "message": "decision must be approve or reject"})),
        )
            .into_response();
    }
    if body.note.as_ref().is_some_and(|n| n.len() > MAX_NOTE_BYTES) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "message": "note too long"})),
        )
            .into_response();
    }
    let url = format!("{}/{id}/decision", app.approvals);
    relay(
        app.client
            .post(url)
            .bearer_auth(token)
            .json(&json!({"decision": body.decision, "note": body.note}))
            .send()
            .await,
    )
    .await
}
fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'".parse().unwrap());
    response
}
/// The decision route is the dashboard's only write. It accepts a browser POST only
/// when the Host is a literal loopback address, the Origin matches that Host exactly
/// and fetch metadata does not mark the request cross-site. Everything else, including
/// non-browser clients without an Origin, is rejected: the operator decides from this
/// page, on this machine.
async fn local_operator_write(req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    let valid_host = host.is_some_and(|h| {
        h.parse::<SocketAddr>().is_ok_and(|a| a.ip().is_loopback())
            || h.strip_prefix("localhost:")
                .is_some_and(|p| p.parse::<u16>().is_ok())
    });
    let valid_origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|o| o.to_str().ok())
        .zip(host)
        .is_some_and(|(origin, host)| origin == format!("http://{host}"));
    let same_site = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v == "same-origin");
    if !valid_host || !valid_origin || !same_site {
        return StatusCode::FORBIDDEN.into_response();
    }
    security_headers(next.run(req).await)
}
fn router(app: App) -> axum::Router {
    let reads = axum::Router::new()
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("style.css"),
                )
            }),
        )
        .route("/api/snapshot", get(data))
        .route("/api/approvals", get(approvals_list))
        .layer(middleware::from_fn(local_only));
    let writes = axum::Router::new()
        .route("/api/approvals/{id}/decision", post(approvals_decide))
        .layer(middleware::from_fn(local_operator_write));
    reads.merge(writes).with_state(app)
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let address = loopback_address(&args.listen)?;
    let audit = audit_url(&args.audit_url)?;
    let approvals = approvals_url(&args.gate_url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("Operator dashboard (audit and approvals): http://{address}");
    axum::serve(
        listener,
        router(App {
            client,
            audit,
            approvals,
        }),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Method, http::Request};
    use tower::ServiceExt;
    const HOLD: &str = "0123456789abcdef0123456789abcdef";
    fn app() -> axum::Router {
        router(App {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            audit: "http://127.0.0.1:1/audit".into(),
            approvals: "http://127.0.0.1:1/v1/approvals".into(),
        })
    }
    fn decision_request(id: &str, body: &str) -> Request<Body> {
        Request::builder()
            .uri(format!("/api/approvals/{id}/decision"))
            .method("POST")
            .header("host", "127.0.0.1:8790")
            .header("origin", "http://127.0.0.1:8790")
            .header("authorization", "Bearer operator-token")
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }
    #[test]
    fn only_literal_local_upstream() {
        for url in [
            "https://127.0.0.1",
            "http://example.com",
            "http://localhost",
            "http://127.0.0.1@evil.com",
            "http://127.0.0.1/path",
            "http://127.0.0.1?secret=x",
        ] {
            assert!(audit_url(url).is_err(), "{url}");
            assert!(approvals_url(url).is_err(), "{url}");
        }
        assert!(audit_url("http://[::1]:8788").is_ok());
        assert_eq!(
            approvals_url("http://127.0.0.1:8787").unwrap(),
            "http://127.0.0.1:8787/v1/approvals"
        );
    }
    #[tokio::test]
    async fn approvals_require_a_bearer_token() {
        let list = app()
            .oneshot(
                Request::builder()
                    .uri("/api/approvals")
                    .header("host", "127.0.0.1:8790")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::UNAUTHORIZED);
        let mut decide = decision_request(HOLD, r#"{"decision":"approve"}"#);
        decide.headers_mut().remove(header::AUTHORIZATION);
        let decide = app().oneshot(decide).await.unwrap();
        assert_eq!(decide.status(), StatusCode::UNAUTHORIZED);
    }
    #[tokio::test]
    async fn decision_input_is_validated_before_relay() {
        for id in [
            "zz3456789abcdef0123456789abcdef",
            "0123456789ABCDEF0123456789abcdef",
            "0123",
        ] {
            let response = app()
                .oneshot(decision_request(id, r#"{"decision":"approve"}"#))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{id}");
        }
        // A path that escapes the route never reaches the handler at all.
        let response = app()
            .oneshot(decision_request("../audit", r#"{"decision":"approve"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        for body in [
            r#"{"decision":"maybe"}"#,
            r#"{"decision":"approve","extra":1}"#,
            "not json",
        ] {
            let response = app().oneshot(decision_request(HOLD, body)).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        }
        let long_note = format!(r#"{{"decision":"reject","note":"{}"}}"#, "x".repeat(1025));
        let response = app()
            .oneshot(decision_request(HOLD, &long_note))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // A valid request passes validation and reaches the relay; with no gate
        // listening the operator gets 502, never a silent accept.
        let response = app()
            .oneshot(decision_request(HOLD, r#"{"decision":"approve"}"#))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
    #[tokio::test]
    async fn decision_rejects_cross_site_posts() {
        // Foreign Origin.
        let mut request = decision_request(HOLD, r#"{"decision":"approve"}"#);
        request
            .headers_mut()
            .insert(header::ORIGIN, "http://evil.example".parse().unwrap());
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // No Origin: not a page-driven decision.
        let mut request = decision_request(HOLD, r#"{"decision":"approve"}"#);
        request.headers_mut().remove(header::ORIGIN);
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // Cross-site fetch metadata.
        let mut request = decision_request(HOLD, r#"{"decision":"approve"}"#);
        request
            .headers_mut()
            .insert("sec-fetch-site", "cross-site".parse().unwrap());
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // Rebinding: foreign Host even with a matching Origin.
        let mut request = decision_request(HOLD, r#"{"decision":"approve"}"#);
        let headers = request.headers_mut();
        headers.insert(header::HOST, "attacker.example:8790".parse().unwrap());
        headers.insert(
            header::ORIGIN,
            "http://attacker.example:8790".parse().unwrap(),
        );
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // Same-origin POST with fetch metadata passes to the relay (no gate: 502).
        let mut request = decision_request(HOLD, r#"{"decision":"approve"}"#);
        request
            .headers_mut()
            .insert("sec-fetch-site", "same-origin".parse().unwrap());
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
    #[tokio::test]
    async fn rejects_writes_and_rebinding() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/snapshot")
                    .method("POST")
                    .header("host", "127.0.0.1:8790")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "attacker.example:8790")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "127.0.0.1:8790")
                    .header("origin", "http://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    #[tokio::test]
    async fn offline_is_unknown_and_uncached() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/snapshot")
                    .header("host", "127.0.0.1:8790")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    #[tokio::test]
    async fn relays_list_and_decision_with_operator_token() {
        use std::sync::{Arc, Mutex};
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_list = seen.clone();
        let seen_decide = seen.clone();
        let mock = axum::Router::new()
            .route(
                "/v1/approvals",
                get(move |headers: HeaderMap| {
                    let seen = seen_list.clone();
                    async move {
                        seen.lock().unwrap().push(format!(
                            "list|{}",
                            headers
                                .get(header::AUTHORIZATION)
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or("")
                        ));
                        Json(json!({"approvals": []}))
                    }
                }),
            )
            .route(
                "/v1/approvals/{id}/decision",
                post(
                    move |Path(id): Path<String>,
                          headers: HeaderMap,
                          Json(body): Json<serde_json::Value>| {
                        let seen = seen_decide.clone();
                        async move {
                            seen.lock().unwrap().push(format!(
                                "decide|{id}|{}|{body}",
                                headers
                                    .get(header::AUTHORIZATION)
                                    .and_then(|h| h.to_str().ok())
                                    .unwrap_or("")
                            ));
                            (StatusCode::OK, Json(json!({"ok": true})))
                        }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        let app = router(App {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            audit: "http://127.0.0.1:1/audit".into(),
            approvals: format!("http://{addr}/v1/approvals"),
        });
        let list = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/approvals")
                    .method(Method::GET)
                    .header("host", "127.0.0.1:8790")
                    .header("authorization", "Bearer operator-oidc-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let decide = app
            .oneshot(decision_request(
                HOLD,
                r#"{"decision":"approve","note":"ticket 1234"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(decide.status(), StatusCode::OK);
        let recorded = seen.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0], "list|Bearer operator-oidc-token");
        assert_eq!(
            recorded[1],
            format!("decide|{HOLD}|Bearer operator-token|{{\"decision\":\"approve\",\"note\":\"ticket 1234\"}}")
        );
    }
}
