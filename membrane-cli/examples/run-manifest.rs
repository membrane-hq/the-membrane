//! Assemble, sign, and verify a signed run manifest for a pilot evidence
//! bundle. The manifest binds run scalars, role pubkeys (each role named
//! separately even when one key fills several roles in the pilot), declared
//! inputs, observed results, and the sha256 of every bundle file. A Schnorr
//! signature over the canonical signable view (the manifest without its
//! `signature` field) binds all of it to the manifest signer key, using the
//! same digest binding as MembraneEvent and the IAC.
//!
//! Modes:
//!   collect --run-json P --roles-json P --inputs-json P --results-json P
//!           --file REL=ABS ... --out P
//!   sign    --manifest P --out P        (key from NOSTR_NSEC_FILE)
//!   verify  --manifest P --bundle DIR [--signer-pubkey HEX]
use anyhow::{bail, Context, Result};
use membrane_cli::signing_key::SigningKeyArgs;
use membrane_core::canonical::canonical_json_bytes;
use membrane_core::nostr_bus::verify_membrane_event_signature;
use membrane_core::{MembraneEvent, SiemEvent};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("collect") => collect(&args[1..]),
        Some("sign") => sign(&args[1..]),
        Some("verify") => verify(&args[1..]),
        _ => bail!("usage: run-manifest <collect|sign|verify> ..."),
    }
}

fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].as_str())
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    opt(args, name).with_context(|| format!("missing required {name}"))
}

fn file_args(args: &[String]) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < args.len() {
        if args[i] == "--file" {
            let (rel, abs) = args[i + 1]
                .split_once('=')
                .context("--file expects REL=ABS")?;
            out.push((rel.to_string(), PathBuf::from(abs)));
        }
        i += 1;
    }
    Ok(out)
}

fn read_json(path: &str) -> Result<Value> {
    let body = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    serde_json::from_str(&body).with_context(|| format!("parse {path}"))
}

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Ok((hex::encode(digest), bytes.len() as u64))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn collect(args: &[String]) -> Result<()> {
    let out = required(args, "--out")?;
    let mut manifest = Map::new();
    manifest.insert("schema".into(), json!("membrane.run-manifest/0.1"));
    manifest.insert("created_at".into(), json!(unix_now()));
    for (key, flag) in [
        ("run", "--run-json"),
        ("roles", "--roles-json"),
        ("inputs", "--inputs-json"),
        ("results", "--results-json"),
    ] {
        let value = read_json(required(args, flag)?)?;
        if !value.is_object() {
            bail!("{flag} must name a JSON object");
        }
        manifest.insert(key.into(), value);
    }
    let mut files_json = Vec::new();
    for (rel, abs) in file_args(args)? {
        let (sha256, bytes) = sha256_file(&abs)?;
        files_json.push(json!({"path": rel, "sha256": sha256, "bytes": bytes}));
    }
    manifest.insert("files".into(), Value::Array(files_json));
    std::fs::write(out, serde_json::to_vec_pretty(&Value::Object(manifest))?)?;
    println!("collected manifest: {out}");
    Ok(())
}

fn sign(args: &[String]) -> Result<()> {
    let manifest_path = required(args, "--manifest")?;
    let out = required(args, "--out")?;
    let mut manifest = read_json(manifest_path)?;
    let obj = manifest
        .as_object_mut()
        .context("manifest must be a JSON object")?;
    obj.remove("signature");
    let bytes = canonical_json_bytes(&*obj)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let message = nostr::secp256k1::Message::from_digest(digest);
    let keys = SigningKeyArgs {
        nsec_file: std::env::var_os("NOSTR_NSEC_FILE").map(PathBuf::from),
        nsec: None,
    }
    .load_keys()?;
    let sig = keys.sign_schnorr(&message);
    obj.insert("signature".into(), json!(hex::encode(sig.serialize())));
    std::fs::write(out, serde_json::to_vec_pretty(&manifest)?)?;
    println!(
        "signed manifest: {out} signer={}",
        keys.public_key().to_hex()
    );
    Ok(())
}

fn verify(args: &[String]) -> Result<()> {
    let manifest_path = required(args, "--manifest")?;
    let bundle = PathBuf::from(required(args, "--bundle")?);
    let manifest = read_json(manifest_path)?;
    let obj = manifest
        .as_object()
        .context("manifest must be a JSON object")?;
    let sig_hex = obj
        .get("signature")
        .and_then(Value::as_str)
        .context("manifest is unsigned")?;
    let roles = obj.get("roles").context("manifest missing roles")?;
    let signer = roles
        .get("manifest_signer_pubkey")
        .and_then(Value::as_str)
        .context("roles.manifest_signer_pubkey missing")?;
    if let Some(expected) = opt(args, "--signer-pubkey") {
        if expected != signer {
            bail!("manifest signer {signer} does not match required {expected}");
        }
    }

    let mut signable = obj.clone();
    signable.remove("signature");
    let bytes = canonical_json_bytes(&signable)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let message = nostr::secp256k1::Message::from_digest(digest);
    let sig_bytes = hex::decode(sig_hex).context("signature is not hex")?;
    let sig = nostr::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
        .context("malformed signature")?;
    let pk_bytes = hex::decode(signer).context("signer pubkey is not hex")?;
    let pk = nostr::secp256k1::XOnlyPublicKey::from_slice(&pk_bytes)
        .context("malformed signer pubkey")?;
    nostr::secp256k1::Secp256k1::verification_only()
        .verify_schnorr(&sig, &message, &pk)
        .map_err(|_| anyhow::anyhow!("manifest signature does not verify"))?;

    // Re-hash every bound file against the bundle directory.
    let files = obj
        .get("files")
        .and_then(Value::as_array)
        .context("manifest missing files")?;
    let mut has_signed_events = false;
    let mut has_evidence = false;
    for entry in files {
        let rel = entry
            .get("path")
            .and_then(Value::as_str)
            .context("file entry missing path")?;
        if rel.contains("..") || rel.starts_with('/') {
            bail!("unsafe bundle path: {rel}");
        }
        let (sha256, bytes) = sha256_file(&bundle.join(rel))?;
        let want_sha = entry
            .get("sha256")
            .and_then(Value::as_str)
            .context("file entry missing sha256")?;
        let want_bytes = entry
            .get("bytes")
            .and_then(Value::as_u64)
            .context("file entry missing bytes")?;
        if sha256 != want_sha || bytes != want_bytes {
            bail!("bundle file {rel} does not match the manifest");
        }
        if rel == "signed-events.jsonl" {
            has_signed_events = true;
        }
        if rel == "evidence.jsonl" {
            has_evidence = true;
        }
    }

    // Receipts: each signed event's domain signature must verify against its
    // own subject key, and the publisher set must match the manifest role.
    let mut event_count = 0usize;
    if has_signed_events {
        let body = std::fs::read_to_string(bundle.join("signed-events.jsonl"))
            .context("read signed-events.jsonl")?;
        let mut subjects = Vec::new();
        let mut expected_by_id: std::collections::BTreeMap<String, SiemEvent> =
            std::collections::BTreeMap::new();
        for line in body.lines().filter(|l| !l.trim().is_empty()) {
            let line: Value = serde_json::from_str(line).context("invalid signed event line")?;
            let nostr_event_id = line
                .get("nostr_event_id")
                .and_then(Value::as_str)
                .context("signed event line missing nostr_event_id")?;
            let event: MembraneEvent = serde_json::from_value(
                line.get("event")
                    .cloned()
                    .context("signed event line missing event")?,
            )
            .context("invalid signed event")?;
            verify_membrane_event_signature(&event, &event.subject_pubkey)
                .context("signed event signature does not verify")?;
            // Recompute the expected projection from the verified event with
            // the exporter's own mapping, keyed by the (unsigned) transport
            // id, for the content correspondence check below.
            let expected = SiemEvent::from_membrane_event(&event, Some(nostr_event_id));
            if expected_by_id
                .insert(nostr_event_id.to_string(), expected)
                .is_some()
            {
                bail!("duplicate nostr_event_id in signed events: {nostr_event_id}");
            }
            subjects.push(event.subject_pubkey);
            event_count += 1;
        }
        subjects.sort();
        subjects.dedup();
        let mut role_pubkeys: Vec<String> = roles
            .get("receipt_publisher_pubkeys")
            .and_then(Value::as_array)
            .context("roles.receipt_publisher_pubkeys missing")?
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        role_pubkeys.sort();
        role_pubkeys.dedup();
        if subjects != role_pubkeys {
            bail!(
                "signed event publishers {subjects:?} do not match \
                 roles.receipt_publisher_pubkeys {role_pubkeys:?}"
            );
        }
        // Content correspondence: the wrapper ids are unsigned, so matching
        // id sets alone would prove nothing. Every projection row must equal
        // the projection recomputed from the cryptographically verified
        // event under that id, with no duplicates and no missing or extra
        // rows.
        if has_evidence {
            let projection = std::fs::read_to_string(bundle.join("evidence.jsonl"))
                .context("read evidence.jsonl")?;
            let mut seen = std::collections::BTreeSet::new();
            for line in projection.lines().filter(|l| !l.trim().is_empty()) {
                let row: SiemEvent =
                    serde_json::from_str(line).context("invalid evidence projection line")?;
                if !seen.insert(row.event_id.clone()) {
                    bail!("duplicate projection event_id: {}", row.event_id);
                }
                let expected = expected_by_id.get(&row.event_id).with_context(|| {
                    format!("projection row {} has no signed event", row.event_id)
                })?;
                if &row != expected {
                    bail!(
                        "projection row {} does not match its verified signed event",
                        row.event_id
                    );
                }
            }
            if seen.len() != expected_by_id.len() {
                bail!(
                    "projection row count {} does not match signed event count {}",
                    seen.len(),
                    expected_by_id.len()
                );
            }
        }
    }

    println!(
        "manifest OK: signer={signer} files={} signed_events={event_count}",
        files.len()
    );
    Ok(())
}
