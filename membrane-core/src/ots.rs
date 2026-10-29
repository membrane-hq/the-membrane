//! OpenTimestamps calendar stamping for signed rollup digests.

use async_trait::async_trait;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct OtsStampResult {
    pub calendar_url: String,
    pub proof_bytes: Vec<u8>,
}

impl OtsStampResult {
    pub fn proof_hex(&self) -> String {
        hex::encode(&self.proof_bytes)
    }

    pub fn proof_b64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(&self.proof_bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OtsError {
    #[error("no calendar URLs configured")]
    NoCalendars,
    #[error("stamp failed: {0}")]
    StampFailed(String),
    #[error("HTTP client: {0}")]
    Http(String),
}

// async_trait adds a redundant must_use to its boxed Future on Rust 1.99.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait OtsStamper: Send + Sync {
    async fn stamp_digest(&self, digest: [u8; 32]) -> Result<OtsStampResult, OtsError>;
}

pub struct HttpOtsStamper {
    client: reqwest::Client,
    calendar_urls: Vec<String>,
}

impl HttpOtsStamper {
    pub fn new(calendar_urls: Vec<String>) -> Result<Self, OtsError> {
        if calendar_urls.is_empty() {
            return Err(OtsError::NoCalendars);
        }
        crate::tls::install_default_provider();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("membrane/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| OtsError::Http(e.to_string()))?;
        Ok(Self {
            client,
            calendar_urls,
        })
    }

    pub fn default_calendars() -> Vec<String> {
        vec![
            "https://a.pool.opentimestamps.org".into(),
            "https://b.pool.opentimestamps.org".into(),
        ]
    }
}

#[async_trait]
impl OtsStamper for HttpOtsStamper {
    async fn stamp_digest(&self, digest: [u8; 32]) -> Result<OtsStampResult, OtsError> {
        let mut last_err = String::new();
        for url in &self.calendar_urls {
            let endpoint = format!("{}/digest", url.trim_end_matches('/'));
            match self
                .client
                .post(&endpoint)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(digest.to_vec())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let bytes = resp
                        .bytes()
                        .await
                        .map_err(|e| OtsError::StampFailed(format!("read body from {url}: {e}")))?;
                    if bytes.is_empty() {
                        last_err = format!("{url}: empty proof");
                        continue;
                    }
                    return Ok(OtsStampResult {
                        calendar_url: url.clone(),
                        proof_bytes: bytes.to_vec(),
                    });
                }
                Ok(resp) => {
                    last_err = format!("{url}: HTTP {}", resp.status());
                }
                Err(e) => {
                    last_err = format!("{url}: {e}");
                }
            }
        }
        Err(OtsError::StampFailed(last_err))
    }
}

pub struct MockOtsStamper;

#[async_trait]
impl OtsStamper for MockOtsStamper {
    async fn stamp_digest(&self, digest: [u8; 32]) -> Result<OtsStampResult, OtsError> {
        let mut h = Sha256::new();
        h.update(b"membrane-mock-ots");
        h.update(digest);
        Ok(OtsStampResult {
            calendar_url: "mock://ots".into(),
            proof_bytes: h.finalize().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_stamper_is_deterministic() {
        let digest = [0xab; 32];
        let s = MockOtsStamper;
        let a = s.stamp_digest(digest).await.unwrap();
        let b = s.stamp_digest(digest).await.unwrap();
        assert_eq!(a.proof_hex(), b.proof_hex());
    }
}
