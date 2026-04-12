/// Anthropic Messages API request/response types.
///
/// Covers:
///   - MessagesRequest (POST /v1/messages)
///   - user_text()   — extract user+system content for scanning
///   - redact()      — replace content with the redacted version
///   - Anthropic's content block format (text, image, tool_use, tool_result)

use serde::{Deserialize, Serialize};

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessagesRequest {
    pub model:       String,
    pub messages:    Vec<AnthropicMessage>,
    pub max_tokens:  u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system:      Option<SystemContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream:      Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p:       Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k:       Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools:       Option<serde_json::Value>,
    #[serde(flatten)]
    pub extra:       serde_json::Map<String, serde_json::Value>,
}

/// System prompt can be a plain string or a list of content blocks.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SystemContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnthropicMessage {
    pub role:    String,  // "user" | "assistant"
    pub content: AnthropicContent,
}

/// Content can be a plain string or a list of content blocks.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AnthropicContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text:       Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source:     Option<serde_json::Value>,  // image source
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id:         Option<String>,             // tool_use id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name:       Option<String>,             // tool name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input:      Option<serde_json::Value>,  // tool input
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content:    Option<serde_json::Value>,  // tool_result content
}

impl MessagesRequest {
    /// Parse from a JSON byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Extract all user-visible text (user messages + system prompt).
    pub fn user_text(&self) -> String {
        let mut parts: Vec<String> = Vec::new();

        // System prompt
        if let Some(sys) = &self.system {
            parts.push(extract_system(sys));
        }

        // User messages (not assistant turns)
        for msg in &self.messages {
            if msg.role != "user" { continue; }
            parts.push(extract_content(&msg.content));
        }

        parts.join("\n")
    }

    /// Return a new request with all user message text replaced by `redacted_text`.
    pub fn with_redacted_content(&self, redacted_text: &str) -> Self {
        let mut req  = self.clone();
        let mut first = true;
        for msg in &mut req.messages {
            if msg.role != "user" { continue; }
            if first {
                msg.content = AnthropicContent::Text(redacted_text.to_owned());
                first = false;
            } else {
                msg.content = AnthropicContent::Text("[redacted]".to_owned());
            }
        }
        // Also clear system prompt if present
        if req.system.is_some() && !first {
            req.system = Some(SystemContent::Text("[redacted]".to_owned()));
        }
        req
    }

    /// Serialize back to JSON bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn is_streaming(&self) -> bool {
        self.stream.unwrap_or(false)
    }
}

fn extract_content(content: &AnthropicContent) -> String {
    match content {
        AnthropicContent::Text(s) => s.clone(),
        AnthropicContent::Blocks(blocks) => {
            blocks.iter()
                .filter(|b| b.block_type == "text")
                .filter_map(|b| b.text.as_deref())
                .collect::<Vec<_>>()
                .join(" ")
        }
    }
}

fn extract_system(sys: &SystemContent) -> String {
    match sys {
        SystemContent::Text(s) => s.clone(),
        SystemContent::Blocks(blocks) => {
            blocks.iter()
                .filter(|b| b.block_type == "text")
                .filter_map(|b| b.text.as_deref())
                .collect::<Vec<_>>()
                .join(" ")
        }
    }
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessagesResponse {
    pub id:           String,
    #[serde(rename = "type")]
    pub resp_type:    String,
    pub role:         String,
    pub content:      Vec<ContentBlock>,
    pub model:        String,
    pub stop_reason:  Option<String>,
    pub stop_sequence: Option<String>,
    pub usage:        Option<AnthropicUsage>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnthropicUsage {
    pub input_tokens:  u32,
    pub output_tokens: u32,
}

// ── Error response builder ────────────────────────────────────────────────────

/// Build an Anthropic-compatible error response JSON body.
pub fn error_response(error_type: &str, message: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type":  "error",
        "error": {
            "type":    error_type,
            "message": message,
        }
    })).unwrap_or_default()
}

fn severity_label(risk: f64) -> &'static str {
    if risk >= 80.0 { "critical" } else if risk >= 60.0 { "high" } else { "medium" }
}

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

/// Build a structured blocked-request error body with span locations.
///
/// Format matches Anthropic error envelope with a `tsm` extension field.
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
        "type": "error",
        "error": {
            "type":    "permission_error",
            "message": "Request blocked by TSM security policy",
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

    const SIMPLE: &[u8] = br#"{
        "model": "claude-3-opus-20240229",
        "max_tokens": 1024,
        "system": "You are helpful.",
        "messages": [
            {"role": "user", "content": "My SSN is 123-45-6789"}
        ]
    }"#;

    #[test]
    fn parse_request() {
        let req = MessagesRequest::from_bytes(SIMPLE).unwrap();
        assert_eq!(req.model, "claude-3-opus-20240229");
        assert_eq!(req.messages.len(), 1);
    }

    #[test]
    fn user_text_includes_system_and_user() {
        let req  = MessagesRequest::from_bytes(SIMPLE).unwrap();
        let text = req.user_text();
        assert!(text.contains("You are helpful."));
        assert!(text.contains("My SSN is 123-45-6789"));
    }

    #[test]
    fn redaction_replaces_user_content() {
        let req     = MessagesRequest::from_bytes(SIMPLE).unwrap();
        let redacted = req.with_redacted_content("[REDACTED:SSN]");
        match &redacted.messages[0].content {
            AnthropicContent::Text(s) => assert_eq!(s, "[REDACTED:SSN]"),
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn multiblock_content_extracted() {
        let raw = br#"{
            "model": "claude-3-sonnet",
            "max_tokens": 256,
            "messages": [{"role": "user", "content": [
                {"type": "text",  "text": "Describe this image:"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "abc"}}
            ]}]
        }"#;
        let req  = MessagesRequest::from_bytes(raw).unwrap();
        let text = req.user_text();
        assert!(text.contains("Describe this image:"));
        assert!(!text.contains("abc")); // image data should not appear
    }

    #[test]
    fn error_response_format() {
        let body: serde_json::Value = serde_json::from_slice(
            &blocked_response(&["SSN".to_string()], 95.0, "block-critical-pii-p10", &[])
        ).unwrap();
        assert_eq!(body["type"].as_str().unwrap(), "error");
        let tsm = &body["error"]["tsm"];
        assert!(tsm["detected"].as_array().unwrap().iter().any(|v| v.as_str() == Some("SSN")));
    }
}
