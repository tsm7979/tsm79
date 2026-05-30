pub mod openai;
pub mod anthropic;
pub mod sse;

pub use openai::{ChatCompletionRequest, ChatMessage, MessageContent, blocked_response as openai_blocked};
pub use anthropic::{MessagesRequest, AnthropicMessage, AnthropicContent, blocked_response as anthropic_blocked};
pub use sse::{SseEvent, parse_events, make_event, done_event, openai_chunk_text, anthropic_chunk_text};

/// Which AI protocol a request is using.
#[derive(Debug, Clone, PartialEq)]
pub enum AiProtocol {
    OpenAI,
    Anthropic,
}

/// A unified AI request — either OpenAI or Anthropic wire format.
pub enum AiRequest {
    OpenAI(ChatCompletionRequest),
    Anthropic(MessagesRequest),
}

impl AiRequest {
    /// Detect protocol from the request path and parse the body.
    pub fn from_path_and_body(path: &[u8], body: &[u8]) -> Result<Self, String> {
        let path_str = std::str::from_utf8(path).unwrap_or("");
        if path_str.contains("/v1/messages") || path_str.contains("/anthropic") {
            let req = MessagesRequest::from_bytes(body)
                .map_err(|e| format!("Anthropic parse error: {}", e))?;
            Ok(AiRequest::Anthropic(req))
        } else {
            // Default: OpenAI-compatible
            let req = ChatCompletionRequest::from_bytes(body)
                .map_err(|e| format!("OpenAI parse error: {}", e))?;
            Ok(AiRequest::OpenAI(req))
        }
    }

    /// Extract user-visible text for scanning.
    pub fn user_text(&self) -> String {
        match self {
            AiRequest::OpenAI(r)    => r.user_text(),
            AiRequest::Anthropic(r) => r.user_text(),
        }
    }

    /// Return the model name.
    pub fn model(&self) -> &str {
        match self {
            AiRequest::OpenAI(r)    => &r.model,
            AiRequest::Anthropic(r) => &r.model,
        }
    }

    /// Return the redacted version of this request as JSON bytes.
    pub fn redacted_bytes(&self, redacted_text: &str) -> Vec<u8> {
        match self {
            AiRequest::OpenAI(r)    => r.with_redacted_content(redacted_text).to_bytes(),
            AiRequest::Anthropic(r) => r.with_redacted_content(redacted_text).to_bytes(),
        }
    }

    /// Whether streaming is requested.
    pub fn is_streaming(&self) -> bool {
        match self {
            AiRequest::OpenAI(r)    => r.is_streaming(),
            AiRequest::Anthropic(r) => r.is_streaming(),
        }
    }

    /// The protocol type.
    pub fn protocol(&self) -> AiProtocol {
        match self {
            AiRequest::OpenAI(_)    => AiProtocol::OpenAI,
            AiRequest::Anthropic(_) => AiProtocol::Anthropic,
        }
    }

    /// Build a structured blocked-request error response for this protocol.
    ///
    /// `rule_name` comes from the policy engine result.
    /// `spans` are `(start, end, pii_type)` byte offsets of detected content.
    pub fn build_block_response(
        &self,
        pii_types:  &[String],
        risk_score: f64,
        rule_name:  &str,
        spans:      &[(usize, usize, String)],
    ) -> Vec<u8> {
        match self {
            AiRequest::OpenAI(_)    => openai_blocked(pii_types, risk_score, rule_name, spans),
            AiRequest::Anthropic(_) => anthropic_blocked(pii_types, risk_score, rule_name, spans),
        }
    }
}
