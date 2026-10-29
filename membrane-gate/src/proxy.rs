use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub id: String,
    pub object: String,
    pub model: String,
    pub choices: Vec<ChatChoice>,
}

/// Environment variable that enables the canned development reply.
pub const ENV_DEV_MOCK_MODEL: &str = "MEMBRANE_DEV_MOCK_MODEL";

pub struct LlmProxy {
    model_api_url: Option<String>,
    dev_mock: bool,
}

impl LlmProxy {
    /// Fails closed: with no reachable backend, `chat` returns an error.
    pub fn new(model_api_url: Option<String>) -> Self {
        Self {
            model_api_url,
            dev_mock: false,
        }
    }

    /// Answer with a canned reply when no backend is configured or reachable.
    /// For local development and tests only.
    pub fn with_dev_mock(mut self, enabled: bool) -> Self {
        self.dev_mock = enabled;
        self
    }

    /// Enable the dev mock when `MEMBRANE_DEV_MOCK_MODEL=1`.
    pub fn with_dev_mock_from_env(self) -> Self {
        let enabled = std::env::var(ENV_DEV_MOCK_MODEL).is_ok_and(|v| v == "1");
        self.with_dev_mock(enabled)
    }

    pub fn model_api_url(&self) -> Option<&str> {
        self.model_api_url.as_deref()
    }

    pub async fn chat(&self, req: &ChatRequest) -> Result<ChatResponse> {
        if req.stream {
            bail!("streaming not supported in Phase 0 gate");
        }
        let outcome = match &self.model_api_url {
            Some(url) => self.provider_chat(url, req).await,
            None => Err(anyhow!("no model_api_url configured")),
        };
        match outcome {
            Ok(resp) => Ok(resp),
            Err(err) if self.dev_mock => {
                warn!(error = %err, "model API unavailable, using dev mock response");
                Ok(mock_response(req))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn complete(&self, model: &str, prompt: &str) -> Result<String> {
        let resp = self
            .chat(&ChatRequest {
                model: model.to_string(),
                messages: vec![ChatMessage {
                    role: "user".into(),
                    content: prompt.to_string(),
                }],
                stream: false,
            })
            .await?;
        Ok(resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default())
    }

    async fn provider_chat(&self, base: &str, req: &ChatRequest) -> Result<ChatResponse> {
        let endpoint = format!("{}/v1/chat/completions", base.trim_end_matches('/'));
        membrane_core::tls::install_default_provider();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        let resp = client
            .post(&endpoint)
            .json(req)
            .send()
            .await
            .context("model API request")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("model API status {status}: {body}");
        }
        let parsed: ChatResponse = resp.json().await.context("model API response")?;
        info!(model = %parsed.model, "model API completion");
        Ok(parsed)
    }
}

fn mock_response(req: &ChatRequest) -> ChatResponse {
    let prompt_len: usize = req.messages.iter().map(|m| m.content.len()).sum();
    ChatResponse {
        id: "membrane-mock".into(),
        object: "chat.completion".into(),
        model: req.model.clone(),
        choices: vec![ChatChoice {
            index: 0,
            message: ChatMessage {
                role: "assistant".into(),
                content: format!("[membrane-mock] received {prompt_len} bytes"),
            },
            finish_reason: Some("stop".into()),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ChatRequest {
        ChatRequest {
            model: "m".into(),
            messages: vec![ChatMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            stream: false,
        }
    }

    #[tokio::test]
    async fn fails_closed_without_backend() {
        let err = LlmProxy::new(None).chat(&request()).await.unwrap_err();
        assert!(err.to_string().contains("no model_api_url"));
    }

    #[tokio::test]
    async fn unreachable_backend_is_an_error() {
        let proxy = LlmProxy::new(Some("http://127.0.0.1:9".into()));
        assert!(proxy.chat(&request()).await.is_err());
    }

    #[tokio::test]
    async fn dev_mock_answers_only_when_enabled() {
        let proxy = LlmProxy::new(None).with_dev_mock(true);
        let resp = proxy.chat(&request()).await.unwrap();
        assert_eq!(resp.id, "membrane-mock");
    }
}
