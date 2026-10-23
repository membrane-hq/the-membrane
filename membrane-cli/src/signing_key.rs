//! Local signing-key sources shared by CLI commands and the walkthrough helper.
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;
use membrane_gate::secret::Secret;
use nostr::Keys;

/// File sources take precedence. A configured but unusable file fails closed.
/// Legacy raw values remain supported, but process arguments/environment can
/// retain copies outside the zeroed text holder.
#[derive(Args, Clone, Debug, Default)]
pub struct SigningKeyArgs {
    /// Preferred: private signing-key file (mode 0600 on Unix)
    #[arg(long, env = "NOSTR_NSEC_FILE", value_name = "PATH")]
    pub nsec_file: Option<PathBuf>,
    /// Legacy raw signing key; prefer --nsec-file to avoid process-list/history exposure
    #[arg(long, value_parser = parse_secret, value_name = "KEY")]
    pub nsec: Option<Secret>,
}

fn parse_secret(value: &str) -> Result<Secret, String> {
    Ok(Secret::new(value))
}

impl SigningKeyArgs {
    pub fn load_keys(self) -> Result<Keys> {
        let secret = if let Some(path) = self.nsec_file {
            Secret::from_file(&path).context("load NOSTR_NSEC_FILE")?
        } else if let Some(secret) = self.nsec {
            secret
        } else {
            match std::env::var("NOSTR_NSEC") {
                Ok(value) => Secret::new(value),
                Err(std::env::VarError::NotPresent) => {
                    bail!("signing key required: use NOSTR_NSEC_FILE or --nsec-file (legacy: NOSTR_NSEC or --nsec)")
                }
                Err(_) => bail!("NOSTR_NSEC is not valid Unicode"),
            }
        };
        // Do not propagate a parser error that could quote secret input.
        Keys::parse(secret.expose()).map_err(|_| anyhow::anyhow!("invalid Nostr signing key"))
    }
}
