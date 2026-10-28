//! GitHub tool connector for the production gate.
//!
//! Enforced only after IAC `tool_allowlist` + repo allowlist checks.
//! Tokens come from env (`MEMBRANE_GITHUB_TOKEN` or `GITHUB_TOKEN`) — never logged.
//! Public demo / `membrane demo` keeps simulated tools and does not mount this path.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::info;

use crate::secret::{Secret, SecretError};

/// Post a comment on an issue or pull request (same GitHub Issues Comments API).
pub const TOOL_GITHUB_COMMENT: &str = "github.comment";
/// Merge a pull request — typically denied by omitting from the IAC allowlist.
pub const TOOL_GITHUB_MERGE: &str = "github.merge";
/// Optional read-only tool id (no network side effect beyond GET).
pub const TOOL_GITHUB_ISSUE_READ: &str = "github.issue.read";

pub const ENV_TOKEN_PRIMARY: &str = "MEMBRANE_GITHUB_TOKEN";
pub const ENV_TOKEN_FALLBACK: &str = "GITHUB_TOKEN";
/// Path to a file holding the token. Preferred over the environment variables:
/// the value never sits in the process environment or on a command line.
pub const ENV_TOKEN_FILE: &str = "MEMBRANE_GITHUB_TOKEN_FILE";
/// When set to `1`/`true`, ignored integration tests may hit live GitHub.
pub const ENV_INTEGRATION: &str = "MEMBRANE_GITHUB_INTEGRATION";

#[derive(Debug, Error)]
pub enum GitHubConnectorError {
    #[error("GitHub token missing; set {ENV_TOKEN_PRIMARY} or {ENV_TOKEN_FALLBACK}")]
    TokenMissing,
    #[error("repo not in gate allowlist: {0}")]
    RepoDenied(String),
    #[error("unsupported GitHub tool: {0}")]
    UnsupportedTool(String),
    #[error("invalid tool arguments: {0}")]
    InvalidArgs(String),
    #[error("GitHub API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("refusing to send the GitHub token to {0}: only https://api.github.com or loopback")]
    CredentialDestination(String),
    #[error("HTTP client error: {0}")]
    Http(String),
}

#[derive(Debug, Clone, Default)]
pub struct GitHubConnectorConfig {
    /// Explicit `owner/name` allowlist. Empty = deny all repos (fail closed).
    pub repo_allowlist: Vec<String>,
    /// Override API base (tests). Default: https://api.github.com
    pub api_base: String,
    /// Connector credential. Redacted in Debug, zeroed on drop.
    pub token: Option<Secret>,
}

impl GitHubConnectorConfig {
    /// Load the token from `MEMBRANE_GITHUB_TOKEN_FILE`, else from
    /// `MEMBRANE_GITHUB_TOKEN` / `GITHUB_TOKEN`. Environment variables are
    /// removed from the process after reading. A configured file that cannot be
    /// used is an error and never falls back to the environment.
    pub fn try_from_env(repo_allowlist: Vec<String>) -> Result<Self, SecretError> {
        let token = Secret::load(ENV_TOKEN_FILE, &[ENV_TOKEN_PRIMARY, ENV_TOKEN_FALLBACK])?;
        Ok(Self {
            repo_allowlist,
            api_base: "https://api.github.com".into(),
            token,
        })
    }

    /// Like `try_from_env`, but an unusable credential file leaves the
    /// connector without a token, so mutating calls fail closed.
    pub fn from_env(repo_allowlist: Vec<String>) -> Self {
        Self::try_from_env(repo_allowlist.clone()).unwrap_or_else(|err| {
            tracing::error!(%err, "github token not loaded; connector has no token");
            Self {
                repo_allowlist,
                api_base: "https://api.github.com".into(),
                token: None,
            }
        })
    }

    /// The token is attached only to `https://api.github.com`, or to a
    /// loopback address for local tests. Production never sets another base
    /// (`from_env` fixes it), so this guards against a future code path or
    /// config option pointing the credential at another host.
    pub fn check_token_destination(&self) -> Result<(), GitHubConnectorError> {
        let denied = || GitHubConnectorError::CredentialDestination(self.api_base.clone());
        let url = reqwest::Url::parse(&self.api_base).map_err(|_| denied())?;
        let host = url
            .host_str()
            .unwrap_or("")
            .trim_matches(|c| c == '[' || c == ']');
        let loopback = host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        match url.scheme() {
            "https" if host == "api.github.com" && url.port().is_none() => Ok(()),
            "http" if loopback => Ok(()),
            _ => Err(denied()),
        }
    }

    pub fn repo_allowed(&self, owner: &str, repo: &str) -> bool {
        let key = format!("{owner}/{repo}");
        self.repo_allowlist.iter().any(|r| r == &key)
    }

    pub fn has_token(&self) -> bool {
        self.token.as_ref().is_some_and(|t| !t.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvokeRequest {
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub model: String,
    pub owner: String,
    pub repo: String,
    #[serde(default)]
    pub issue_number: Option<u64>,
    #[serde(default)]
    pub pull_number: Option<u64>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub commit_title: Option<String>,
}

/// Digest-only context for the CP Merkle tree — never includes comment body or tokens.
#[derive(Debug, Clone, Serialize)]
pub struct ToolReceiptContext {
    pub tool: String,
    pub model: String,
    pub owner: String,
    pub repo: String,
    pub simulation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

pub fn body_sha256_hex(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

pub fn is_github_tool(tool_id: &str) -> bool {
    matches!(
        tool_id,
        TOOL_GITHUB_COMMENT | TOOL_GITHUB_MERGE | TOOL_GITHUB_ISSUE_READ
    )
}

/// Pure policy checks that must pass before any GitHub HTTP call.
pub fn authorize_repo_and_args(
    config: &GitHubConnectorConfig,
    req: &ToolInvokeRequest,
) -> Result<(), GitHubConnectorError> {
    if !is_github_tool(&req.tool) {
        return Err(GitHubConnectorError::UnsupportedTool(req.tool.clone()));
    }
    if req.owner.is_empty()
        || req.repo.is_empty()
        || !req
            .owner
            .bytes()
            .chain(req.repo.bytes())
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || req.owner == "."
        || req.owner == ".."
        || req.repo == "."
        || req.repo == ".."
    {
        return Err(GitHubConnectorError::InvalidArgs(
            "owner and repo are required".into(),
        ));
    }
    if !config.repo_allowed(&req.owner, &req.repo) {
        return Err(GitHubConnectorError::RepoDenied(format!(
            "{}/{}",
            req.owner, req.repo
        )));
    }
    match req.tool.as_str() {
        TOOL_GITHUB_COMMENT => {
            if req.issue_number.is_none() && req.pull_number.is_none() {
                return Err(GitHubConnectorError::InvalidArgs(
                    "issue_number or pull_number required for github.comment".into(),
                ));
            }
            if req
                .body
                .as_ref()
                .map(|b| b.trim().is_empty())
                .unwrap_or(true)
            {
                return Err(GitHubConnectorError::InvalidArgs(
                    "body required for github.comment".into(),
                ));
            }
        }
        TOOL_GITHUB_MERGE => {
            if req.pull_number.is_none() {
                return Err(GitHubConnectorError::InvalidArgs(
                    "pull_number required for github.merge".into(),
                ));
            }
        }
        TOOL_GITHUB_ISSUE_READ if req.issue_number.is_none() && req.pull_number.is_none() => {
            return Err(GitHubConnectorError::InvalidArgs(
                "issue_number or pull_number required for github.issue.read".into(),
            ));
        }
        TOOL_GITHUB_ISSUE_READ => {}
        _ => {}
    }
    Ok(())
}

pub struct GitHubConnector {
    config: GitHubConnectorConfig,
    client: reqwest::Client,
}

impl GitHubConnector {
    pub fn new(config: GitHubConnectorConfig) -> Self {
        membrane_core::tls::install_default_provider();
        let client = reqwest::Client::builder()
            .user_agent("membrane-gate-github-connector/0.1")
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("reqwest client");
        Self { config, client }
    }

    pub fn config(&self) -> &GitHubConnectorConfig {
        &self.config
    }

    /// Validate repo/args and (for mutating tools) token presence — still no HTTP.
    pub fn preflight(&self, req: &ToolInvokeRequest) -> Result<(), GitHubConnectorError> {
        authorize_repo_and_args(&self.config, req)?;
        if matches!(
            req.tool.as_str(),
            TOOL_GITHUB_COMMENT | TOOL_GITHUB_MERGE | TOOL_GITHUB_ISSUE_READ
        ) {
            if !self.config.has_token() {
                return Err(GitHubConnectorError::TokenMissing);
            }
            self.config.check_token_destination()?;
        }
        Ok(())
    }

    /// Execute a GitHub tool. Caller must already have passed `Gate::authorize_tool`.
    pub async fn execute(
        &self,
        req: &ToolInvokeRequest,
    ) -> Result<ToolReceiptContext, GitHubConnectorError> {
        self.preflight(req)?;
        let token = self
            .config
            .token
            .as_ref()
            .ok_or(GitHubConnectorError::TokenMissing)?;

        info!(
            tool = %req.tool,
            owner = %req.owner,
            repo = %req.repo,
            "github connector invoking (token redacted)"
        );

        match req.tool.as_str() {
            TOOL_GITHUB_COMMENT => self.post_comment(token, req).await,
            TOOL_GITHUB_MERGE => self.merge_pull(token, req).await,
            TOOL_GITHUB_ISSUE_READ => self.read_issue(token, req).await,
            other => Err(GitHubConnectorError::UnsupportedTool(other.into())),
        }
    }

    /// GET-only observation. GitHub cannot prove operation attribution for these tools.
    pub async fn observe(&self, req: &ToolInvokeRequest) -> Result<Value, GitHubConnectorError> {
        self.preflight(req)?;
        let suffix = match req.tool.as_str() {
            TOOL_GITHUB_COMMENT => format!(
                "issues/{}/comments?per_page=100",
                req.issue_number.or(req.pull_number).unwrap()
            ),
            TOOL_GITHUB_MERGE => format!("pulls/{}", req.pull_number.unwrap()),
            _ => return Err(GitHubConnectorError::UnsupportedTool(req.tool.clone())),
        };
        let url = format!(
            "{}/repos/{}/{}/{}",
            self.config.api_base.trim_end_matches('/'),
            req.owner,
            req.repo,
            suffix
        );
        let response = self
            .client
            .get(url)
            .bearer_auth(self.config.token.as_ref().unwrap().expose())
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| GitHubConnectorError::Http(e.to_string()))?;
        if !response.status().is_success() {
            return Ok(
                json!({"observation":"unverifiable", "http_status":response.status().as_u16()}),
            );
        }
        let paginated = response.headers().contains_key("link");
        // Bound untrusted evidence before parsing; do not store bodies or tokens.
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| GitHubConnectorError::Http(e.to_string()))?
        {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Ok(json!({"observation":"unverifiable", "reason":"response_size_limit"}));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| GitHubConnectorError::Http(e.to_string()))?;
        if req.tool == TOOL_GITHUB_COMMENT {
            let comments = value.as_array().ok_or_else(|| {
                GitHubConnectorError::Http("comments response is not an array".into())
            })?;
            let ids: Vec<_> = comments
                .iter()
                .filter(|c| {
                    c.get("body")
                        .and_then(Value::as_str)
                        .is_some_and(|b| Some(b) == req.body.as_deref())
                })
                .filter_map(|c| c.get("id").and_then(Value::as_u64))
                .collect();
            Ok(
                json!({"observation":"comment_candidates", "matching_ids":ids, "history_complete":!paginated && comments.len() < 100, "attribution_verified":false}),
            )
        } else {
            Ok(
                json!({"observation":"pull_state", "merged":value.get("merged").and_then(Value::as_bool), "merge_commit_sha":value.get("merge_commit_sha").and_then(Value::as_str), "attribution_verified":false}),
            )
        }
    }

    async fn post_comment(
        &self,
        token: &Secret,
        req: &ToolInvokeRequest,
    ) -> Result<ToolReceiptContext, GitHubConnectorError> {
        let number = req.issue_number.or(req.pull_number).unwrap();
        let body = req.body.as_deref().unwrap_or("");
        let url = format!(
            "{}/repos/{}/{}/issues/{}/comments",
            self.config.api_base.trim_end_matches('/'),
            req.owner,
            req.repo,
            number
        );
        let resp = self
            .client
            .post(&url)
            .bearer_auth(token.expose())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&json!({ "body": body }))
            .send()
            .await
            .map_err(|e| GitHubConnectorError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| GitHubConnectorError::Http(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(GitHubConnectorError::Api {
                status,
                message: redact_tokenish(&token.scrub(&text)),
            });
        }
        let parsed: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        Ok(ToolReceiptContext {
            tool: req.tool.clone(),
            model: req.model.clone(),
            owner: req.owner.clone(),
            repo: req.repo.clone(),
            simulation: false,
            issue_number: Some(number),
            pull_number: req.pull_number,
            body_sha256: Some(body_sha256_hex(body)),
            result: Some(json!({
                "comment_id": parsed.get("id"),
                "html_url": parsed.get("html_url"),
            })),
        })
    }

    async fn merge_pull(
        &self,
        token: &Secret,
        req: &ToolInvokeRequest,
    ) -> Result<ToolReceiptContext, GitHubConnectorError> {
        let pull_number = req.pull_number.unwrap();
        let url = format!(
            "{}/repos/{}/{}/pulls/{}/merge",
            self.config.api_base.trim_end_matches('/'),
            req.owner,
            req.repo,
            pull_number
        );
        let mut payload = json!({});
        if let Some(title) = &req.commit_title {
            payload["commit_title"] = json!(title);
        }
        let resp = self
            .client
            .put(&url)
            .bearer_auth(token.expose())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&payload)
            .send()
            .await
            .map_err(|e| GitHubConnectorError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| GitHubConnectorError::Http(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(GitHubConnectorError::Api {
                status,
                message: redact_tokenish(&token.scrub(&text)),
            });
        }
        let parsed: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        Ok(ToolReceiptContext {
            tool: req.tool.clone(),
            model: req.model.clone(),
            owner: req.owner.clone(),
            repo: req.repo.clone(),
            simulation: false,
            issue_number: None,
            pull_number: Some(pull_number),
            body_sha256: None,
            result: Some(json!({
                "merged": parsed.get("merged"),
                "sha": parsed.get("sha"),
            })),
        })
    }

    async fn read_issue(
        &self,
        token: &Secret,
        req: &ToolInvokeRequest,
    ) -> Result<ToolReceiptContext, GitHubConnectorError> {
        let number = req.issue_number.or(req.pull_number).unwrap();
        let url = format!(
            "{}/repos/{}/{}/issues/{}",
            self.config.api_base.trim_end_matches('/'),
            req.owner,
            req.repo,
            number
        );
        let resp = self
            .client
            .get(&url)
            .bearer_auth(token.expose())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| GitHubConnectorError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| GitHubConnectorError::Http(e.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(GitHubConnectorError::Api {
                status,
                message: redact_tokenish(&token.scrub(&text)),
            });
        }
        let parsed: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let title = parsed.get("title").and_then(|v| v.as_str()).unwrap_or("");
        Ok(ToolReceiptContext {
            tool: req.tool.clone(),
            model: req.model.clone(),
            owner: req.owner.clone(),
            repo: req.repo.clone(),
            simulation: false,
            issue_number: Some(number),
            pull_number: req.pull_number,
            body_sha256: None,
            result: Some(json!({
                "number": parsed.get("number"),
                "state": parsed.get("state"),
                "title_sha256": body_sha256_hex(title),
                "html_url": parsed.get("html_url"),
            })),
        })
    }
}

fn redact_tokenish(s: &str) -> String {
    // Keep error text short; never echo likely secrets.
    let trimmed = if s.len() > 240 { &s[..240] } else { s };
    trimmed
        .replace("ghp_", "[redacted]")
        .replace("github_pat_", "[redacted]")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(repos: &[&str]) -> GitHubConnectorConfig {
        GitHubConnectorConfig {
            repo_allowlist: repos.iter().map(|s| (*s).to_string()).collect(),
            api_base: "http://127.0.0.1:9".into(),
            token: Some("test-token".into()),
        }
    }

    #[test]
    fn deny_repo_not_on_allowlist_before_http() {
        let config = cfg(&["acme/allowed"]);
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "other".into(),
            issue_number: Some(1),
            pull_number: None,
            body: Some("hi".into()),
            commit_title: None,
        };
        let err = authorize_repo_and_args(&config, &req).unwrap_err();
        assert!(matches!(err, GitHubConnectorError::RepoDenied(_)));
    }

    #[test]
    fn empty_allowlist_denies_all_repos() {
        let config = cfg(&[]);
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "x".into(),
            issue_number: Some(1),
            pull_number: None,
            body: Some("hi".into()),
            commit_title: None,
        };
        assert!(matches!(
            authorize_repo_and_args(&config, &req),
            Err(GitHubConnectorError::RepoDenied(_))
        ));
    }

    #[test]
    fn allow_comment_args_on_listed_repo() {
        let config = cfg(&["acme/allowed"]);
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "allowed".into(),
            issue_number: Some(7),
            pull_number: None,
            body: Some("membrane pilot comment".into()),
            commit_title: None,
        };
        authorize_repo_and_args(&config, &req).unwrap();
    }

    #[test]
    fn preflight_requires_token_without_calling_github() {
        let config = GitHubConnectorConfig {
            repo_allowlist: vec!["acme/allowed".into()],
            api_base: "http://127.0.0.1:9".into(),
            token: None,
        };
        let connector = GitHubConnector::new(config);
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "allowed".into(),
            issue_number: Some(1),
            pull_number: None,
            body: Some("x".into()),
            commit_title: None,
        };
        let err = connector.preflight(&req).unwrap_err();
        assert!(matches!(err, GitHubConnectorError::TokenMissing));
    }

    #[test]
    fn body_digest_is_stable_and_not_plaintext() {
        let dig = body_sha256_hex("secret-in-comment");
        assert_eq!(dig.len(), 64);
        assert!(!dig.contains("secret"));
    }

    #[tokio::test]
    async fn mock_http_posts_comment_after_preflight() {
        use axum::{routing::post, Json, Router};
        use std::net::SocketAddr;
        use tokio::sync::oneshot;

        let (tx, rx) = oneshot::channel::<()>();
        let app = Router::new().route(
            "/repos/acme/allowed/issues/3/comments",
            post(|| async {
                Json(json!({
                    "id": 99,
                    "html_url": "https://github.com/acme/allowed/issues/3#issuecomment-99"
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .ok();
        });

        let config = GitHubConnectorConfig {
            repo_allowlist: vec!["acme/allowed".into()],
            api_base: format!("http://{addr}"),
            token: Some("test-token".into()),
        };
        let connector = GitHubConnector::new(config);
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "allowed".into(),
            issue_number: Some(3),
            pull_number: None,
            body: Some("hello from membrane".into()),
            commit_title: None,
        };
        let ctx = connector.execute(&req).await.unwrap();
        assert!(!ctx.simulation);
        assert_eq!(
            ctx.body_sha256.as_deref(),
            Some(body_sha256_hex("hello from membrane").as_str())
        );
        assert_eq!(ctx.result.as_ref().unwrap()["comment_id"], 99);
        let _ = tx.send(());
        let _addr: SocketAddr = addr;
    }

    fn comment_req() -> ToolInvokeRequest {
        ToolInvokeRequest {
            operation_id: Some("op".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "demo".into(),
            owner: "acme".into(),
            repo: "allowed".into(),
            issue_number: Some(3),
            pull_number: None,
            body: Some("hi".into()),
            commit_title: None,
        }
    }

    #[test]
    fn config_debug_does_not_show_token() {
        let config = GitHubConnectorConfig {
            repo_allowlist: vec!["acme/allowed".into()],
            api_base: "https://api.github.com".into(),
            token: Some("synthetic-token-debug-check".into()),
        };
        assert!(!format!("{config:?}").contains("synthetic-token-debug-check"));
    }

    #[test]
    fn token_is_only_sent_to_api_github_com_or_loopback() {
        let mut config = cfg(&["acme/allowed"]);
        for ok in [
            "https://api.github.com",
            "http://127.0.0.1:8080",
            "http://localhost:1",
        ] {
            config.api_base = ok.into();
            assert!(config.check_token_destination().is_ok(), "{ok}");
        }
        for bad in [
            "http://api.github.com",
            "http://evil.example",
            "ftp://127.0.0.1",
            "not a url",
        ] {
            config.api_base = bad.into();
            assert!(config.check_token_destination().is_err(), "{bad}");
        }
        config.api_base = "http://evil.example".into();
        let connector = GitHubConnector::new(config);
        assert!(matches!(
            connector.preflight(&comment_req()),
            Err(GitHubConnectorError::CredentialDestination(_))
        ));
    }

    #[tokio::test]
    async fn upstream_error_that_echoes_the_token_is_scrubbed() {
        use axum::{http::StatusCode, routing::post, Router};
        let app = Router::new().route(
            "/repos/acme/allowed/issues/3/comments",
            post(|| async {
                (
                    StatusCode::UNAUTHORIZED,
                    "bad credentials: synthetic-echoed-token-77",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        let connector = GitHubConnector::new(GitHubConnectorConfig {
            repo_allowlist: vec!["acme/allowed".into()],
            api_base: format!("http://{addr}"),
            token: Some("synthetic-echoed-token-77".into()),
        });
        let err = connector.execute(&comment_req()).await.unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("synthetic-echoed-token-77"), "{shown}");
        assert!(shown.contains("[redacted]"));
    }

    #[tokio::test]
    #[ignore = "set MEMBRANE_GITHUB_INTEGRATION=1 with a valid token + disposable repo"]
    async fn live_github_integration() {
        let enabled = std::env::var(ENV_INTEGRATION)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !enabled {
            return;
        }
        let owner = std::env::var("MEMBRANE_GITHUB_OWNER").expect("MEMBRANE_GITHUB_OWNER");
        let repo = std::env::var("MEMBRANE_GITHUB_REPO").expect("MEMBRANE_GITHUB_REPO");
        let issue: u64 = std::env::var("MEMBRANE_GITHUB_ISSUE")
            .unwrap_or_else(|_| "1".into())
            .parse()
            .unwrap();
        let config = GitHubConnectorConfig::from_env(vec![format!("{owner}/{repo}")]);
        let connector = GitHubConnector::new(config);
        let req = ToolInvokeRequest {
            operation_id: Some("test-operation".into()),
            tool: TOOL_GITHUB_COMMENT.into(),
            model: "integration".into(),
            owner,
            repo,
            issue_number: Some(issue),
            pull_number: None,
            body: Some("Membrane integration check (safe to delete)".into()),
            commit_title: None,
        };
        let ctx = connector.execute(&req).await.unwrap();
        assert!(ctx.result.is_some());
    }
}

#[cfg(test)]
mod reconciliation_tests {
    use super::*;
    #[tokio::test]
    async fn merge_and_paginated_comments_are_observations_not_proof() {
        let app = axum::Router::new()
            .route(
                "/repos/acme/pilot/pulls/1",
                axum::routing::get(|| async {
                    axum::Json(json!({"merged":true,"merge_commit_sha":"abc"}))
                }),
            )
            .route(
                "/repos/acme/pilot/issues/1/comments",
                axum::routing::get(|| async {
                    (
                        [("link", "<https://invalid.test/next>; rel=next")],
                        axum::Json(json!([])),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connector = GitHubConnector::new(GitHubConnectorConfig {
            repo_allowlist: vec!["acme/pilot".into()],
            api_base: format!("http://{}", listener.local_addr().unwrap()),
            token: Some("test".into()),
        });
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut req: ToolInvokeRequest = serde_json::from_value(json!({"tool":"github.merge","model":"demo","owner":"acme","repo":"pilot","pull_number":1})).unwrap();
        let evidence = connector.observe(&req).await.unwrap();
        assert_eq!(evidence["merged"], true);
        assert_eq!(evidence["attribution_verified"], false);
        req.tool = TOOL_GITHUB_COMMENT.into();
        req.body = Some("hello".into());
        let evidence = connector.observe(&req).await.unwrap();
        assert_eq!(evidence["history_complete"], false);
        assert_eq!(evidence["attribution_verified"], false);
        req.owner = "acme/../evil".into();
        assert!(connector.observe(&req).await.is_err());
        task.abort();
    }
}
