//! One provider interface for any model.
//!
//! `anthropic` calls the Claude Messages API over HTTP (no official Rust SDK
//! exists): adaptive thinking, structured JSON output against the role's
//! schema, and server side refusal fallbacks. `openai_compatible` serves
//! local models (vLLM, llama.cpp server, Ollama) behind an OpenAI compatible
//! endpoint, which is how the spec's vetted local model is reached.

use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct AiRequest {
    pub system: String,
    pub prompt: String,
    /// JSON schema the response must match.
    pub schema: Value,
    pub max_tokens: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AiResponse {
    pub json: Value,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ProviderError {
    #[error("model declined the request ({0})")]
    Refused(String),
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("provider returned malformed output: {0}")]
    Malformed(String),
    #[error("credential unavailable: {0}")]
    Credential(String),
}

pub trait AiProvider: Send + Sync {
    fn name(&self) -> &str;
    fn complete(&self, r: &AiRequest) -> Result<AiResponse, ProviderError>;
    /// USD per million input and output tokens.
    fn price_per_mtok(&self) -> (f64, f64);
    /// Local providers keep data inside the company.
    fn is_local(&self) -> bool;
}

/// HTTP transport, so the providers are testable and the server can choose
/// its client.
pub trait HttpTransport: Send + Sync {
    fn post_json(&self, url: &str, headers: &[(&str, String)], body: &Value) -> Result<(u16, Value), String>;
}

pub struct UreqTransport {
    agent: ureq::Agent,
}

impl Default for UreqTransport {
    fn default() -> Self {
        UreqTransport { agent: ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(600)).build() }
    }
}

impl HttpTransport for UreqTransport {
    fn post_json(&self, url: &str, headers: &[(&str, String)], body: &Value) -> Result<(u16, Value), String> {
        let mut req = self.agent.post(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.send_json(body.clone()) {
            Ok(r) => {
                let status = r.status();
                r.into_json::<Value>().map(|v| (status, v)).map_err(|e| e.to_string())
            }
            Err(ureq::Error::Status(code, r)) => Ok((code, r.into_json::<Value>().unwrap_or(Value::Null))),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Resolves `secret_ref` values (vault://..., env://...). The model never
/// sees the credential.
pub trait SecretResolver: Send + Sync {
    fn resolve(&self, secret_ref: &str) -> Option<String>;
}

/// env://NAME reads an environment variable; other schemes need a broker.
pub struct EnvSecrets;

impl SecretResolver for EnvSecrets {
    fn resolve(&self, r: &str) -> Option<String> {
        r.strip_prefix("env://").and_then(|n| std::env::var(n).ok())
    }
}

pub const ANTHROPIC_DEFAULT_MODEL: &str = "claude-opus-5-5";
const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2026-10-21";
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";

pub struct AnthropicProvider<T: HttpTransport, S: SecretResolver> {
    pub name: String,
    pub model: String,
    pub secret_ref: String,
    pub url: String,
    pub price: (f64, f64),
    transport: T,
    secrets: S,
}

impl<T: HttpTransport, S: SecretResolver> AnthropicProvider<T, S> {
    pub fn new(name: &str, model: Option<&str>, secret_ref: &str, transport: T, secrets: S) -> Self {
        AnthropicProvider {
            name: name.into(),
            model: model.unwrap_or(ANTHROPIC_DEFAULT_MODEL).into(),
            secret_ref: secret_ref.into(),
            url: ANTHROPIC_URL.into(),
            price: (4.0, 20.0),
            transport,
            secrets,
        }
    }

    pub fn request_body(&self, r: &AiRequest) -> Value {
        json!({
            "model": self.model,
            "max_tokens": r.max_tokens,
            "thinking": { "type": "adaptive" },
            "output_config": { "effort": "high", "format": { "type": "json_schema", "schema": r.schema } },
            "fallbacks": "default",
            "system": r.system,
            "messages": [{ "role": "user", "content": r.prompt }]
        })
    }
}

impl<T: HttpTransport, S: SecretResolver> AiProvider for AnthropicProvider<T, S> {
    fn name(&self) -> &str {
        &self.name
    }
    fn price_per_mtok(&self) -> (f64, f64) {
        self.price
    }
    fn is_local(&self) -> bool {
        false
    }
    fn complete(&self, r: &AiRequest) -> Result<AiResponse, ProviderError> {
        let key = self.secrets.resolve(&self.secret_ref).ok_or_else(|| ProviderError::Credential(self.secret_ref.clone()))?;
        let headers = [
            ("x-api-key", key),
            ("anthropic-version", ANTHROPIC_VERSION.to_string()),
            ("anthropic-beta", FALLBACK_BETA.to_string()),
            ("content-type", "application/json".to_string()),
        ];
        let (status, v) = self.transport.post_json(&self.url, &headers, &self.request_body(r)).map_err(ProviderError::Unavailable)?;
        if status == 429 || status >= 500 {
            return Err(ProviderError::Unavailable(format!("status {status}")));
        }
        if status != 200 {
            return Err(ProviderError::Malformed(format!("status {status}: {}", v.pointer("/error/message").and_then(Value::as_str).unwrap_or(""))));
        }
        if v.get("stop_reason").and_then(Value::as_str) == Some("refusal") {
            let category = v.pointer("/stop_details/category").and_then(Value::as_str).unwrap_or("unspecified");
            return Err(ProviderError::Refused(category.into()));
        }
        let text: String = v
            .get("content")
            .and_then(Value::as_array)
            .map(|blocks| blocks.iter().filter(|b| b.get("type").and_then(Value::as_str) == Some("text")).filter_map(|b| b.get("text").and_then(Value::as_str)).collect())
            .unwrap_or_default();
        let json: Value = serde_json::from_str(&text).map_err(|e| ProviderError::Malformed(e.to_string()))?;
        Ok(AiResponse {
            json,
            model: v.get("model").and_then(Value::as_str).unwrap_or(&self.model).to_string(),
            input_tokens: v.pointer("/usage/input_tokens").and_then(Value::as_u64).unwrap_or(0),
            output_tokens: v.pointer("/usage/output_tokens").and_then(Value::as_u64).unwrap_or(0),
        })
    }
}

/// A local model behind an OpenAI compatible endpoint.
pub struct OpenAiCompatibleProvider<T: HttpTransport> {
    pub name: String,
    pub endpoint: String,
    pub model: String,
    transport: T,
}

impl<T: HttpTransport> OpenAiCompatibleProvider<T> {
    pub fn new(name: &str, endpoint: &str, model: Option<&str>, transport: T) -> Self {
        OpenAiCompatibleProvider { name: name.into(), endpoint: endpoint.trim_end_matches('/').into(), model: model.unwrap_or("local").into(), transport }
    }
}

impl<T: HttpTransport> AiProvider for OpenAiCompatibleProvider<T> {
    fn name(&self) -> &str {
        &self.name
    }
    fn price_per_mtok(&self) -> (f64, f64) {
        (0.0, 0.0)
    }
    fn is_local(&self) -> bool {
        true
    }
    fn complete(&self, r: &AiRequest) -> Result<AiResponse, ProviderError> {
        let body = json!({
            "model": self.model,
            "max_tokens": r.max_tokens,
            "messages": [{ "role": "system", "content": r.system }, { "role": "user", "content": r.prompt }],
            "response_format": { "type": "json_schema", "json_schema": { "name": "ivar_output", "strict": true, "schema": r.schema } }
        });
        let (status, v) = self
            .transport
            .post_json(&format!("{}/chat/completions", self.endpoint), &[("content-type", "application/json".to_string())], &body)
            .map_err(ProviderError::Unavailable)?;
        if status != 200 {
            return Err(ProviderError::Unavailable(format!("status {status}")));
        }
        let text = v.pointer("/choices/0/message/content").and_then(Value::as_str).unwrap_or("");
        let json: Value = serde_json::from_str(text).map_err(|e| ProviderError::Malformed(e.to_string()))?;
        Ok(AiResponse {
            json,
            model: self.model.clone(),
            input_tokens: v.pointer("/usage/prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
            output_tokens: v.pointer("/usage/completion_tokens").and_then(Value::as_u64).unwrap_or(0),
        })
    }
}
