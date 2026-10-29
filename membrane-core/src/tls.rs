//! TLS crypto provider for outbound clients.
//!
//! Every outbound client in the workspace (reqwest, the pinned SIEM client and
//! the Nostr relay websocket) picks its rustls crypto provider from the
//! process-wide default. This module installs that default once.
//!
//! Default: the aws-lc-rs provider, which offers the hybrid X25519MLKEM768 key
//! exchange first and falls back to classical X25519 or P-256/P-384 when the
//! server does not support it. Certificate validation, pinning and TLS 1.3
//! requirements are unchanged by the key exchange.
//!
//! Operators can opt out with `MEMBRANE_TLS_KEY_EXCHANGE=classical`, which
//! installs the ring provider (no hybrid group). The hybrid ClientHello is
//! about 1.2 KB larger than the classical one, so a middlebox that mishandles
//! large hellos is the reason to use the opt-out.
//!
//! Both providers are compiled in. rustls refuses to guess between two
//! providers, so a client built before a default is installed can panic
//! (the Nostr websocket does). Call [`install_default_provider`] before
//! building any client; it is cheap and idempotent. If the embedding process
//! already installed a default, that default is kept.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

/// Environment variable selecting the outbound key-exchange policy.
pub const ENV_KEY_EXCHANGE: &str = "MEMBRANE_TLS_KEY_EXCHANGE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchange {
    /// Offer X25519MLKEM768 first, classical groups as fallback.
    Hybrid,
    /// Classical groups only (X25519, P-256, P-384).
    Classical,
}

impl KeyExchange {
    /// Parse the setting. Unset or empty means hybrid; anything unknown is an
    /// error so a typo is not silently ignored.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            None => Ok(Self::Hybrid),
            Some(v) if v.eq_ignore_ascii_case("hybrid") => Ok(Self::Hybrid),
            Some(v) if v.eq_ignore_ascii_case("classical") => Ok(Self::Classical),
            Some(v) => Err(format!(
                "{ENV_KEY_EXCHANGE} must be \"hybrid\" or \"classical\", got {v:?}"
            )),
        }
    }

    fn from_env() -> Self {
        match Self::parse(std::env::var(ENV_KEY_EXCHANGE).ok().as_deref()) {
            Ok(mode) => mode,
            Err(err) => {
                tracing::warn!("{err}; using hybrid");
                Self::Hybrid
            }
        }
    }
}

/// The provider for a key-exchange policy.
pub fn provider_for(mode: KeyExchange) -> CryptoProvider {
    match mode {
        KeyExchange::Hybrid => rustls::crypto::aws_lc_rs::default_provider(),
        KeyExchange::Classical => rustls::crypto::ring::default_provider(),
    }
}

/// Install the process-wide default provider if none is installed yet. Safe to
/// call from every client constructor and from several threads.
pub fn install_default_provider() {
    if CryptoProvider::get_default().is_none() {
        // An Err means another thread or the host application won the race;
        // either way a default is now installed.
        let _ = provider_for(KeyExchange::from_env()).install_default();
    }
}

/// The provider an explicitly configured client (for example the pinned SIEM
/// client) should use: the installed default, installing ours first if needed.
pub fn provider() -> Arc<CryptoProvider> {
    install_default_provider();
    CryptoProvider::get_default()
        .cloned()
        .expect("a default crypto provider is installed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::NamedGroup;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn groups(p: &CryptoProvider) -> Vec<NamedGroup> {
        p.kx_groups.iter().map(|g| g.name()).collect()
    }

    #[test]
    fn setting_parses_and_rejects_typos() {
        assert_eq!(KeyExchange::parse(None), Ok(KeyExchange::Hybrid));
        assert_eq!(KeyExchange::parse(Some("  ")), Ok(KeyExchange::Hybrid));
        assert_eq!(KeyExchange::parse(Some("Hybrid")), Ok(KeyExchange::Hybrid));
        assert_eq!(
            KeyExchange::parse(Some("classical")),
            Ok(KeyExchange::Classical)
        );
        assert!(KeyExchange::parse(Some("pq-only")).is_err());
    }

    #[test]
    fn hybrid_provider_prefers_mlkem_and_keeps_classical_fallback() {
        let g = groups(&provider_for(KeyExchange::Hybrid));
        assert_eq!(g[0], NamedGroup::X25519MLKEM768);
        assert!(g.contains(&NamedGroup::X25519));
        assert!(g.contains(&NamedGroup::secp256r1));
    }

    #[test]
    fn classical_provider_has_no_mlkem_group() {
        let g = groups(&provider_for(KeyExchange::Classical));
        assert!(!g.contains(&NamedGroup::X25519MLKEM768));
        assert!(g.contains(&NamedGroup::X25519));
    }

    #[test]
    fn install_is_idempotent_and_keeps_an_existing_default() {
        install_default_provider();
        let first = CryptoProvider::get_default().cloned().unwrap();
        install_default_provider();
        let second = CryptoProvider::get_default().cloned().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(&first, &provider()));
    }

    /// A run with `MEMBRANE_TLS_KEY_EXCHANGE=classical` in the environment is
    /// the one legitimate reason for the hybrid tests to skip.
    fn classical_requested() -> bool {
        KeyExchange::parse(std::env::var(ENV_KEY_EXCHANGE).ok().as_deref())
            == Ok(KeyExchange::Classical)
    }

    fn assert_default_is_hybrid() {
        assert_eq!(
            CryptoProvider::get_default().unwrap().kx_groups[0].name(),
            NamedGroup::X25519MLKEM768,
            "installed default must offer the hybrid group first"
        );
    }

    struct TestServer {
        port: u16,
        cert: rustls::pki_types::CertificateDer<'static>,
        group: std::sync::mpsc::Receiver<Option<NamedGroup>>,
    }

    /// One-shot HTTPS server on loopback. `mode` picks the server's provider so
    /// a classical-only peer can be simulated. It reports the negotiated group.
    fn https_server(mode: KeyExchange) -> TestServer {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::try_from(ck.key_pair.serialize_der()).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider_for(mode)))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, group) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(cfg)).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf);
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
            let _ = tls.flush();
            let _ = tx.send(conn.negotiated_key_exchange_group().map(|g| g.name()));
        });
        TestServer { port, cert, group }
    }

    async fn get(server: &TestServer) -> reqwest::Result<String> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_der(&server.cert).unwrap())
            .timeout(Duration::from_secs(10))
            .build()?;
        client
            .get(format!("https://localhost:{}/", server.port))
            .send()
            .await?
            .text()
            .await
    }

    // The default reqwest client (no per-client TLS config) must pick up the
    // installed provider and negotiate the hybrid group with a capable server.
    #[tokio::test]
    async fn default_reqwest_client_negotiates_hybrid_with_capable_server() {
        install_default_provider();
        if classical_requested() {
            return;
        }
        assert_default_is_hybrid();
        let server = https_server(KeyExchange::Hybrid);
        assert_eq!(get(&server).await.unwrap(), "ok");
        assert_eq!(
            server.group.recv().unwrap(),
            Some(NamedGroup::X25519MLKEM768)
        );
    }

    // A classical-only server must still work: the client falls back to X25519.
    #[tokio::test]
    async fn default_reqwest_client_falls_back_with_classical_server() {
        install_default_provider();
        let server = https_server(KeyExchange::Classical);
        assert_eq!(get(&server).await.unwrap(), "ok");
        assert_eq!(server.group.recv().unwrap(), Some(NamedGroup::X25519));
    }

    // The Nostr websocket client builds its TLS config from the process
    // default. With both providers compiled in it panics when none is
    // installed, so connecting must install one, and its ClientHello must
    // offer the hybrid group.
    #[tokio::test]
    async fn nostr_relay_client_installs_a_provider_and_offers_hybrid() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut acceptor = rustls::server::Acceptor::default();
            let offered = loop {
                if acceptor.read_tls(&mut sock).is_err() {
                    break None;
                }
                match acceptor.accept() {
                    Ok(Some(accepted)) => {
                        break accepted.client_hello().named_groups().map(|g| g.to_vec())
                    }
                    Ok(None) => continue,
                    Err(_) => break None,
                }
            };
            let _ = tx.send(offered);
        });
        let url = format!("wss://localhost:{port}");
        let task = tokio::spawn(async move {
            let _ = crate::nostr_bus::fetch_membrane_bus_events(&url, None, 1).await;
        });
        let offered = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(20)))
            .await
            .unwrap()
            .expect("the relay client sent a ClientHello")
            .expect("ClientHello lists named groups");
        task.abort();
        if classical_requested() {
            return;
        }
        assert_default_is_hybrid();
        assert_eq!(offered[0], NamedGroup::X25519MLKEM768);
        assert!(offered.contains(&NamedGroup::X25519));
    }
    const CHILD_MODE: &str = "MEMBRANE_TLS_TEST_CHILD_MODE";
    const CHILD_TEST: &str = "tls::tests::fresh_process_child";

    /// Runs only inside the child processes spawned below, where the process
    /// default is installed from the environment for the first time.
    #[tokio::test]
    async fn fresh_process_child() {
        let Ok(mode) = std::env::var(CHILD_MODE) else {
            return;
        };
        install_default_provider();
        let first = CryptoProvider::get_default().unwrap().kx_groups[0].name();
        let server = https_server(KeyExchange::Hybrid);
        assert_eq!(get(&server).await.unwrap(), "ok");
        let negotiated = server.group.recv().unwrap();
        match mode.as_str() {
            "hybrid" => {
                assert_eq!(first, NamedGroup::X25519MLKEM768);
                assert_eq!(negotiated, Some(NamedGroup::X25519MLKEM768));
            }
            "classical" => {
                assert_ne!(first, NamedGroup::X25519MLKEM768);
                assert_eq!(negotiated, Some(NamedGroup::X25519));
            }
            other => panic!("unknown child mode {other}"),
        }
    }

    fn run_child(mode: &str, setting: &str) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
            .env(ENV_KEY_EXCHANGE, setting)
            .env(CHILD_MODE, mode)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "child {mode} failed:\n{stdout}\n{stderr}"
        );
        // The child must really have run the test, not filtered it out.
        assert!(
            stdout.contains("1 passed"),
            "child {mode} ran no test:\n{stdout}"
        );
    }

    #[test]
    fn explicit_classical_setting_is_honored_in_a_fresh_process() {
        run_child("classical", "classical");
    }

    #[test]
    fn explicit_hybrid_setting_is_honored_in_a_fresh_process() {
        run_child("hybrid", "hybrid");
    }
}
