//! Every test runs the CLI in a separate process with generated local keys.
use nostr::{Keys, ToBech32};
use std::{path::PathBuf, process::Command};

struct Fixture {
    dir: PathBuf,
    key: String,
    pubkey: String,
}
impl Fixture {
    fn new() -> Self {
        let keys = Keys::generate();
        let dir =
            std::env::temp_dir().join(format!("membrane-signing-{}", keys.public_key().to_hex()));
        std::fs::create_dir(&dir).unwrap();
        let key = keys.secret_key().to_bech32().unwrap();
        let path = dir.join("key");
        std::fs::write(&path, format!("  {key}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self {
            dir,
            key,
            pubkey: keys.public_key().to_hex(),
        }
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_membrane"));
        cmd.env_remove("NOSTR_NSEC")
            .env_remove("NOSTR_NSEC_FILE")
            .args(["iac", "sign", "--input", "missing-input", "--out", "unused"]);
        cmd
    }
    fn key_parsed(&self, mut cmd: Command) {
        let out = cmd.output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Signing-key loading happens before input loading, without a relay.
        assert!(!out.status.success());
        assert!(stderr.contains("read IAC input"), "{stderr}");
        assert!(!stderr.contains(&self.key));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[test]
fn file_env_and_flag_sources_parse_the_same_key() {
    let f = Fixture::new();
    let path = f.dir.join("key");
    let args = membrane_cli::signing_key::SigningKeyArgs {
        nsec_file: Some(path.clone()),
        nsec: None,
    };
    assert_eq!(args.load_keys().unwrap().public_key().to_hex(), f.pubkey);
    let mut cmd = f.command();
    cmd.env("NOSTR_NSEC_FILE", &path);
    f.key_parsed(cmd);
    let mut cmd = f.command();
    cmd.arg("--nsec-file").arg(&path);
    f.key_parsed(cmd);
    let mut cmd = f.command();
    cmd.env("NOSTR_NSEC", &f.key);
    f.key_parsed(cmd);
    let mut cmd = f.command();
    cmd.arg("--nsec").arg(&f.key);
    f.key_parsed(cmd);
}

#[test]
fn file_wins_over_legacy_values_and_explicit_path_wins_over_env_path() {
    let f = Fixture::new();
    let mut cmd = f.command();
    cmd.env("NOSTR_NSEC_FILE", f.dir.join("key"))
        .env("NOSTR_NSEC", "invalid-env")
        .args(["--nsec", "invalid-flag"]);
    f.key_parsed(cmd);
    let mut cmd = f.command();
    cmd.env("NOSTR_NSEC_FILE", f.dir.join("missing"))
        .arg("--nsec-file")
        .arg(f.dir.join("key"));
    f.key_parsed(cmd);
    let mut cmd = f.command();
    cmd.env("NOSTR_NSEC", "invalid-env")
        .arg("--nsec")
        .arg(&f.key);
    f.key_parsed(cmd);
}

#[test]
fn unusable_file_never_falls_back_and_errors_do_not_echo_values() {
    let f = Fixture::new();
    std::fs::write(f.dir.join("key"), "\n  ").unwrap();
    for path in [f.dir.join("missing"), f.dir.join("key"), f.dir.clone()] {
        let mut cmd = f.command();
        cmd.env("NOSTR_NSEC_FILE", path)
            .env("NOSTR_NSEC", &f.key)
            .arg("--nsec")
            .arg(&f.key);
        let out = cmd.output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success());
        assert!(err.contains("load NOSTR_NSEC_FILE"), "{err}");
        assert!(!err.contains(&f.key));
        assert!(!err.contains("read IAC input"));
    }
    let mut cmd = f.command();
    cmd.arg("--nsec").arg("invalid-secret-sentinel");
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("invalid Nostr signing key"));
    assert!(!err.contains("invalid-secret-sentinel"));
}

#[cfg(unix)]
#[test]
fn group_readable_file_is_rejected_even_with_valid_fallback() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let path = f.dir.join("key");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let out = f
        .command()
        .env("NOSTR_NSEC_FILE", path)
        .env("NOSTR_NSEC", &f.key)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("chmod 600"));
    assert!(!err.contains(&f.key));
}

#[test]
fn missing_key_and_help_do_not_echo_legacy_env() {
    let f = Fixture::new();
    let out = f.command().output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("signing key required"));
    let out = f
        .command()
        .env("NOSTR_NSEC", &f.key)
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--nsec-file"));
    assert!(!text.contains(&f.key));
}

#[test]
fn file_input_signs_a_verifiable_iac_without_network() {
    let f = Fixture::new();
    let output = f.dir.join("signed.json");
    let out = Command::new(env!("CARGO_BIN_EXE_membrane"))
        .env_remove("NOSTR_NSEC")
        .env_remove("NOSTR_NSEC_FILE")
        .args(["iac", "sign", "--nsec-file"])
        .arg(f.dir.join("key"))
        .arg("--input")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tools/demo-iac.json"))
        .arg("--out")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let raw = std::fs::read_to_string(output).unwrap();
    assert!(!raw.contains(&f.key));
    let iac: membrane_core::IntentAuthorizationCredential = serde_json::from_str(&raw).unwrap();
    iac.verify_signature(&f.pubkey).unwrap();
}

#[test]
fn every_signing_command_exposes_file_source_and_never_displays_raw_env() {
    let f = Fixture::new();
    let mut commands: Vec<Vec<&str>> = vec![
        vec!["chat"],
        vec!["sever"],
        vec!["iac-smoke"],
        vec!["bus", "publish-test"],
        vec!["gate", "start"],
        vec!["session", "status"],
        vec!["session", "receipts"],
        vec!["iac", "issue"],
        vec!["iac", "reissue"],
        vec!["iac", "sign"],
        vec!["tools", "invoke"],
    ];
    if cfg!(feature = "ots") {
        for sub in ["export", "sign", "stamp", "daily"] {
            commands.push(vec!["rollup", sub]);
        }
    }
    for command in commands {
        let out = Command::new(env!("CARGO_BIN_EXE_membrane"))
            .env_remove("NOSTR_NSEC_FILE")
            .env("NOSTR_NSEC", &f.key)
            .args(&command)
            .arg("--help")
            .output()
            .unwrap();
        assert!(out.status.success(), "{command:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("--nsec-file"), "{command:?}");
        assert!(!text.contains(&f.key), "{command:?}");
    }
}

#[test]
fn invalid_file_key_and_empty_path_fail_closed() {
    let f = Fixture::new();
    std::fs::write(f.dir.join("key"), "invalid-file-secret-sentinel").unwrap();
    let out = f
        .command()
        .env("NOSTR_NSEC_FILE", f.dir.join("key"))
        .env("NOSTR_NSEC", &f.key)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("invalid Nostr signing key"));
    assert!(!err.contains("invalid-file-secret-sentinel"));
    let out = f
        .command()
        .env("NOSTR_NSEC_FILE", "")
        .env("NOSTR_NSEC", &f.key)
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn args_debug_redacts_raw_key() {
    let f = Fixture::new();
    let args = membrane_cli::signing_key::SigningKeyArgs {
        nsec_file: None,
        nsec: Some(membrane_gate::secret::Secret::new(&f.key)),
    };
    let debug = format!("{args:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains(&f.key));
    assert_eq!(args.load_keys().unwrap().public_key().to_hex(), f.pubkey);
}
