/// Server-Sent Events (SSE) parser and encoder.
///
/// Used for streaming AI responses from OpenAI and Anthropic.
/// SSE format per W3C spec:
///   - Lines starting with "data: " carry the event payload
///   - "data: [DONE]" signals end of stream
///   - Blank lines separate events
///   - "event:", "id:", "retry:" lines are passed through
///
/// The proxy:
///   1. Receives SSE from the upstream AI
///   2. Parses each event to extract completion text chunks
///   3. Re-encodes and forwards to the client

// ── SSE event ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data:  String,
    pub id:    Option<String>,
    pub retry: Option<u64>,
}

impl SseEvent {
    /// Whether this is the final [DONE] sentinel event.
    pub fn is_done(&self) -> bool {
        self.data.trim() == "[DONE]"
    }

    /// Encode back to SSE wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.data.len());
        if let Some(id) = &self.id {
            out.extend_from_slice(b"id: ");
            out.extend_from_slice(id.as_bytes());
            out.push(b'\n');
        }
        if let Some(event) = &self.event {
            out.extend_from_slice(b"event: ");
            out.extend_from_slice(event.as_bytes());
            out.push(b'\n');
        }
        // Multi-line data: each line gets its own "data: " prefix
        for line in self.data.lines() {
            out.extend_from_slice(b"data: ");
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        if self.data.is_empty() {
            out.extend_from_slice(b"data: \n");
        }
        out.push(b'\n'); // blank line terminates event
        out
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Incrementally parse SSE events from a byte buffer.
///
/// Returns a list of complete events and the number of bytes consumed
/// from the front of `buf`.  Incomplete events at the tail are left for
/// the next call.
pub fn parse_events(buf: &[u8]) -> (Vec<SseEvent>, usize) {
    let text     = match std::str::from_utf8(buf) {
        Ok(s)  => s,
        Err(_) => return (vec![], 0),
    };
    let mut events:   Vec<SseEvent> = Vec::new();
    let mut consumed: usize         = 0;

    // Split on double newlines (event separators)
    let mut current = SseEventBuilder::default();
    let mut line_start = 0;

    let bytes = text.as_bytes();
    while line_start < bytes.len() {
        // Find end of line (\n or \r\n)
        let (line_end, next_start) = match find_newline(&bytes[line_start..]) {
            Some((le, ns)) => (line_start + le, line_start + ns),
            None           => break, // no complete line remaining
        };

        let line = &text[line_start..line_end];
        line_start = next_start;

        if line.is_empty() {
            // Blank line: dispatch the current event if it has data
            if current.has_data {
                events.push(current.build());
                current = SseEventBuilder::default();
            }
            consumed = line_start;
            continue;
        }

        // Parse field:value
        if let Some(colon) = line.find(':') {
            let field = &line[..colon];
            let value = line[colon + 1..].trim_start_matches(' ');
            match field {
                "data"  => { current.data.push_str(value); current.has_data = true; }
                "event" => { current.event = Some(value.to_owned()); }
                "id"    => { current.id    = Some(value.to_owned()); }
                "retry" => { current.retry = value.parse().ok(); }
                _       => {} // ignore unknown fields
            }
        } else if !line.starts_with(':') {
            // Line with no colon and no comment: treat as field with empty value
            match line {
                "data"  => { current.has_data = true; }
                _       => {}
            }
        }
        // Lines starting with ':' are comments — ignore
    }

    (events, consumed)
}

#[derive(Default)]
struct SseEventBuilder {
    data:     String,
    event:    Option<String>,
    id:       Option<String>,
    retry:    Option<u64>,
    has_data: bool,
}

impl SseEventBuilder {
    fn build(self) -> SseEvent {
        SseEvent { event: self.event, data: self.data, id: self.id, retry: self.retry }
    }
}

fn find_newline(buf: &[u8]) -> Option<(usize, usize)> {
    for i in 0..buf.len() {
        if buf[i] == b'\n' {
            let end   = if i > 0 && buf[i - 1] == b'\r' { i - 1 } else { i };
            return Some((end, i + 1));
        }
    }
    None
}

// ── OpenAI streaming chunk extraction ────────────────────────────────────────

/// Extract the text delta from an OpenAI streaming SSE event.
/// Returns the chunk text, or `None` if the event has no delta content.
pub fn openai_chunk_text(event: &SseEvent) -> Option<String> {
    if event.is_done() { return None; }
    let v: serde_json::Value = serde_json::from_str(&event.data).ok()?;
    v["choices"][0]["delta"]["content"]
        .as_str()
        .map(|s| s.to_owned())
}

/// Extract the text delta from an Anthropic streaming SSE event.
pub fn anthropic_chunk_text(event: &SseEvent) -> Option<String> {
    if event.is_done() { return None; }
    let v: serde_json::Value = serde_json::from_str(&event.data).ok()?;
    let event_type = v["type"].as_str()?;
    match event_type {
        "content_block_delta" => v["delta"]["text"].as_str().map(|s| s.to_owned()),
        _ => None,
    }
}

/// Build a single SSE data event.
pub fn make_event(data: &str) -> Vec<u8> {
    SseEvent {
        event: None,
        data:  data.to_owned(),
        id:    None,
        retry: None,
    }.encode()
}

/// Build the terminal [DONE] event.
pub fn done_event() -> Vec<u8> {
    make_event("[DONE]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_event() {
        let input = b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n";
        let (events, consumed) = parse_events(input);
        assert_eq!(events.len(), 1);
        assert_eq!(consumed, input.len());
        assert!(!events[0].is_done());
    }

    #[test]
    fn parse_done_event() {
        let input = b"data: [DONE]\n\n";
        let (events, _) = parse_events(input);
        assert_eq!(events.len(), 1);
        assert!(events[0].is_done());
    }

    #[test]
    fn parse_multiple_events() {
        let input = b"data: foo\n\ndata: bar\n\ndata: [DONE]\n\n";
        let (events, consumed) = parse_events(input);
        assert_eq!(events.len(), 3);
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn partial_event_not_consumed() {
        let input = b"data: hello\n";  // no blank line yet
        let (events, consumed) = parse_events(input);
        assert!(events.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn encode_roundtrip() {
        let ev = SseEvent { event: Some("message".into()), data: "test".into(), id: Some("1".into()), retry: None };
        let encoded = ev.encode();
        let (parsed, _) = parse_events(&encoded);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].data, "test");
        assert_eq!(parsed[0].event.as_deref(), Some("message"));
    }

    #[test]
    fn openai_chunk_text_extracted() {
        let ev = SseEvent {
            event: None,
            data: r#"{"choices":[{"delta":{"content":"Hello"}}]}"#.into(),
            id: None, retry: None,
        };
        assert_eq!(openai_chunk_text(&ev).as_deref(), Some("Hello"));
    }

    #[test]
    fn anthropic_chunk_text_extracted() {
        let ev = SseEvent {
            event: None,
            data: r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}"#.into(),
            id: None, retry: None,
        };
        assert_eq!(anthropic_chunk_text(&ev).as_deref(), Some("Hi"));
    }
}
