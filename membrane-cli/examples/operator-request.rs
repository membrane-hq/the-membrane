//! Local operator walkthrough helper. Keys are generated locally, never printed.
use anyhow::{bail, Context, Result};
use membrane_core::{caller::CallerProof, IntentAuthorizationCredential};
use nostr::{Keys, ToBech32};
use serde::Serialize;
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[tokio::main]
async fn main() -> Result<()> {
    membrane_core::tls::install_default_provider();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("setup") if args.len() == 2 || args.len() == 3 => {
            let dir = Path::new(&args[1]);
            std::fs::create_dir_all(dir)?;
            let path = dir.join("keys.json");
            anyhow::ensure!(!path.exists(), "refusing to overwrite keys");
            let operator = Keys::generate();
            let caller = Keys::generate();
            write_key_file(&dir.join("operator.nsec"), &operator)?;
            write_key_file(&dir.join("caller.nsec"), &caller)?;
            let keys = serde_json::json!({
                "operator_nsec": operator.secret_key().to_bech32()?,
                "operator_pubkey": operator.public_key().to_hex(),
                "caller_nsec": caller.secret_key().to_bech32()?,
                "caller_pubkey": caller.public_key().to_hex(),
            });
            std::fs::write(&path, serde_json::to_vec_pretty(&keys)?)?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            let repos: Vec<&str> = args.get(2).map(|s| vec![s.as_str()]).unwrap_or_default();
            let registry = serde_json::json!({
                "permitted_channels": ["local-llm"],
                "forbidden_exports": ["cloud-telemetry", "training-retention"],
                "model_allowlist": ["sha256:demo-model"],
                "delta_t_secs": 300,
                "model_api_url": "http://127.0.0.1:8080",
                "github_repo_allowlist": repos,
                "identities": { caller.public_key().to_hex(): {
                    "revoked": false,
                    "scopes": ["pilot-scope"], "permitted_channels": ["local-llm"],
                    "model_allowlist": ["sha256:demo-model"],
                    "tool_allowlist": ["github.comment", "github.issue.read"],
                    "github_repo_allowlist": repos
                }}
            });
            std::fs::write(dir.join("registry.yaml"), serde_yaml::to_string(&registry)?)?;
            println!("Local keys and exact pilot-scope grant written to {}", dir.display());
        }
        Some("sign") if args.len() == 7 => {
            let gate_url = args[1].trim_end_matches('/');
            let gate_pubkey = &args[2];
            let iac: IntentAuthorizationCredential = serde_json::from_slice(&std::fs::read(&args[3])?)?;
            iac.verify_signature(gate_pubkey)?;
            let keys = membrane_cli::signing_key::SigningKeyArgs {
                nsec_file: std::env::var_os("NOSTR_NSEC_FILE").map(Into::into),
                nsec: None,
            }.load_keys()?;
            anyhow::ensure!(iac.caller_pubkey.as_deref() == Some(keys.public_key().to_hex().as_str()), "wrong caller key");
            let route = &args[4];
            let raw = std::fs::read(&args[5])?;
            let health: serde_json::Value = reqwest::Client::new().get(format!("{gate_url}/health"))
                .send().await?.error_for_status()?.json().await?;
            let audience = health["caller_audience"].as_str().context("caller audience missing")?;
            anyhow::ensure!(audience.starts_with(&format!("{gate_pubkey}:")), "foreign gate audience");
            let dir = Path::new(&args[6]);
            std::fs::create_dir_all(dir)?;
            match route.as_str() {
                "/v1/chat/completions" => write_request(&keys, audience, route, &iac,
                    &serde_json::from_slice::<membrane_gate::ChatRequest>(&raw)?, dir)?,
                "/v1/tools/invoke" => write_request(&keys, audience, route, &iac,
                    &serde_json::from_slice::<membrane_gate::ToolInvokeRequest>(&raw)?, dir)?,
                _ => bail!("unsupported route"),
            }
            println!("Signed body.json and headers.txt written to {} (send within 60 seconds)", dir.display());
        }
        _ => bail!("usage: operator-request setup DIR [owner/repo] | sign GATE_URL GATE_PUBKEY IAC ROUTE BODY_JSON OUT_DIR"),
    }
    Ok(())
}

fn write_request<T: Serialize>(
    keys: &Keys,
    audience: &str,
    route: &str,
    iac: &IntentAuthorizationCredential,
    body: &T,
    dir: &Path,
) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let proof = CallerProof::sign(
        keys,
        audience,
        route,
        body,
        iac,
        now,
        Keys::generate().public_key().to_hex(),
    )?;
    std::fs::write(dir.join("body.json"), serde_json::to_vec(body)?)?;
    std::fs::write(
        dir.join("headers.txt"),
        format!(
            "Content-Type: application/json\nX-Membrane-IAC: {}\nX-Membrane-Caller-Proof: {}\n",
            serde_json::to_string(iac)?,
            serde_json::to_string(&proof)?
        ),
    )?;
    Ok(())
}

fn write_key_file(path: &Path, keys: &Keys) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let text = membrane_gate::secret::Secret::new(keys.secret_key().to_bech32()?);
    file.write_all(text.expose().as_bytes())?;
    Ok(())
}
