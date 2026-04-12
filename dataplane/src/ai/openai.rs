/// OpenAI Chat Completions API request/response types.
///
/// Covers:
///   - ChatCompletionRequest (POST /v1/chat/completions)
///   - user_text() — extract concatenated user+system message content
///   - redact()    — replace message content with the redacted version
///   - Streaming response (SSE) is handled in ai/sse.rs

use serde::{Deserialize, Serialize};

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatCompletionRequest {
    pub model:             String,
    pub messages:          Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature:       Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens:        Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream:            Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p:             Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty:  Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop:              Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user:              Option<String>,
    /// Passthrough for any fields we don't explicitly model.
    #[serde(flatten)]
    pub extra:             serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatMessage {
    pub role:    String,
    pub content: MessageContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name:    Option<String>,
}

/// Content can be a plain string or a list of content parts (vision API).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContentPart {
    #[serde(rename = "type")]
    pub part_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text:      Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<serde_json::Value>,
}

impl ChatCompletionRequest {
    /// Parse from a JSON byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Extract all user-visible text (user + system messages) concatenated
    /// with newline separators.  This is the text passed to the detector.
    pub fn user_text(&self) -> String {
        self.messages
            .iter()
            .filter(|m| matches!(m.role.as_str(), "user" | "system"))
            .map(|m| match &m.content {
                MessageContent::Text(s)   => s.clone(),
                MessageContent::Parts(ps) => ps.iter()
                    .filter_map(|p| p.text.as_deref())
                    .collect::<Vec<_>>()
                    .join(" "),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Return a new request with all user/system message content replaced by
    /// `redacted_text`.  Only the first user message is replaced; others are
    /// cleared to avoid leaking context while preserving conversation structure.
    pub fn with_redacted_content(&self, redacted_text: &str) -> Self {
        let mut req    = self.clone();
        let mut first  = true;
        for msg in &mut req.messages {
            if matches!(msg.role.as_str(), "user" | "system") {
                if first {
                    msg.content = MessageContent::Text(redacted_text.to_owned());
                    first = false;
                } else {
                    msg.content = MessageContent::Text("[redacted]".to_owned());
                }
            }
        }
        req
    }

    /// Serialize back to JSON bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Whether streaming is requested.
    pub fn is_streaming(&self) -> bool {
        self.stream.unwrap_or(false)
    }
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatCompletionResponse {
    pub id:      String,
    pub object:  String,
    pub created: u64,
    pub model:   String,
    pub choices: Vec<Choice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage:   Option<Usage>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Choice {
    pub index:         u32,
    pub message:       Option<ChatMessage>,
    pub delta:         Option<ChatMessage>,  // used in streaming
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Usage {
    pub prompt_tokens:     u32,
    pub completion_tokens: u32,
    pub total_tokens:      u32,
}

// ── Error response builder ────────────────────────────────────────────────────

/// Build an OpenAI-compatible error response JSON body.
pub fn error_response(code: &str, message: &str, status: u16) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": message,
            "type":    "tsm_policy_error",
            "code":    code,
            "status":  status,
        }
    })).unwrap_or_default()
}

/// Severity label derived from risk score.
fn severity_label(risk: f64) -> &'static str {
    if risk >= 80.0 { "critical" } else if risk >= 60.0 { "high" } else { "medium" }
}

/// Static remediation message keyed on the detected PII types.
fn remediation(pii_types: &[String]) -> &'static str {
    if pii_types.iter().any(|t| t.ends_with("_KEY") || t.ends_with("_TOKEN") || t == "PRIVATE_KEY") {
        "Remove API keys and secrets from message content. Use environment variables or a secrets manager."
    } else if pii_types.iter().any(|t| t == "SSN" || t == "CREDIT_CARD") {
        "Do not include personal financial identifiers in AI prompts."
    } else if pii_types.iter().any(|t| t == "EMAIL" || t == "PHONE") {
        "Consider anonymizing or pseudonymizing personal contact information."
    } else if pii_types.iter().any(|t| t == "JAILBREAK") {
        "Request contains content that violates usage policy."
    } else {
        "Review message content and remove sensitive information before retrying."
    }
}

/// Build a structured blocked-request error response with span locations.
///
/// Format matches OpenAI error envelope with a `tsm` extension field:
/// `{"error":{"type":"content_policy_violation","tsm":{...spans...}}}`
pub fn blocked_response(
    pii_types:  &[String],
    risk_score: f64,
    rule_name:  &str,
    spans:      &[(usize, usize, String)],
) -> Vec<u8> {
    let span_json: Vec<serde_json::Value> = spans.iter().map(|(s, e, t)| {
        serde_json::json!({"start": s, "end": e, "type": t})
    }).collect();

    serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": "Request blocked by TSM security policy",
            "type":    "content_policy_violation",
            "code":    "tsm_policy_block",
            "param":   null,
            "tsm": {
                "rule":        rule_name,
                "risk_score":  risk_score as u64,
                "severity":    severity_label(risk_score),
                "detected":    pii_types,
                "spans":       span_json,
                "remediation": remediation(pii_types),
            }
        }
    })).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_REQUEST: &[u8] = br#"{
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user",   "content": "My SSN is 123-45-6789"}
        ]
    }"#;

    #[test]
    fn parse_request() {
        let req = ChatCompletionRequest::from_bytes(SIMPLE_REQUEST).unwrap();
        assert_eq!(req.model, "gpt-4o");
        assert_eq!(req.messages.len(), 2);
    }

    #[test]
    fn user_text_extracts_both_roles() {
        let req  = ChatCompletionRequest::from_bytes(SIMPLE_REQUEST).unwrap();
        let text = req.user_text();
        assert!(text.contains("You are helpful."));
        assert!(text.contains("My SSN is 123-45-6789"));
    }

    #[test]
    fn redaction_replaces_first_user_message() {
        let req     = ChatCompletionRequest::from_bytes(SIMPLE_REQUEST).unwrap();
        let redacted = req.with_redacted_content("[REDACTED:SSN]");
        let texts: Vec<String> = redacted.messages.iter().map(|m| match &m.content {
            MessageContent::Text(s)  => s.clone(),
            MessageContent::Parts(_) => String::new(),
        }).collect();
        // system message (index 0) → replaced
        assert_eq!(texts[0], "[REDACTED:SSN]");
        // user message (index 1) → "[redacted]"
        assert_eq!(texts[1], "[redacted]");
    }

    #[test]
    fn roundtrip_serialize() {
        let req     = ChatCompletionRequest::from_bytes(SIMPLE_REQUEST).unwrap();
        let bytes   = req.to_bytes();
        let req2    = ChatCompletionRequest::from_bytes(&bytes).unwrap();
        assert_eq!(req2.model, req.model);
    }

    #[test]
    fn error_response_format() {
        let body: serde_json::Value = serde_json::from_slice(
            &blocked_response(&["SSN".to_string()], 95.0, "block-critical-pii-p10", &[])
        ).unwrap();
        let tsm = &body["error"]["tsm"];
        assert!(tsm["detected"].as_array().unwrap().iter().any(|v| v.as_str() == Some("SSN")));
        assert_eq!(tsm["rule"].as_str().unwrap(), "block-critical-pii-p10");
    }

    #[test]
    fn multipart_content_extracted() {
        let raw = br#"{
            "model": "gpt-4-vision",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "What is in this image?"},
                {"type": "image_url", "image_url": {"url": "data:..."}}
            ]}]
        }"#;
        let req = ChatCompletionRequest::from_bytes(raw).unwrap();
        let text = req.user_text();
        assert!(text.contains("What is in this image?"));
    }
}
