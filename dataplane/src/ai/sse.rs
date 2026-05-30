/// Server-Sent Events (SSE) parser, encoder, and sliding-window redaction buffer.
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
///   3. Feeds events through `SseRedactBuffer` — events safe past the lookahead
///      window are forwarded immediately; the tail is scanned and optionally
///      redacted when [DONE] arrives
///   4. Re-encodes and forwards to the client

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

// ── Upstream kind ──────────────────────────────────────────────────────────────

/// Which upstream API format the stream uses — controls delta extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamKind {
    OpenAI,
    Anthropic,
}

// ── Sliding-window streaming redaction buffer ──────────────────────────────────

/// Minimum chars held in the lookahead tail before forwarding.
///
/// 200 chars covers the longest PII pattern (OpenAI key ~50 chars) plus
/// surrounding context, with margin for multi-event spans.
const STREAM_LOOKAHEAD: usize = 200;

/// Buffers SSE events in a sliding-window tail to detect and redact PII that
/// might span across multiple streaming chunk boundaries.
///
/// Events whose text falls entirely before the lookahead window are forwarded
/// immediately (preserving streaming TTFT for clean content).  When `[DONE]`
/// arrives the remaining tail is scanned once and any PII is redacted before
/// the buffered events are flushed to the client.
pub struct SseRedactBuffer {
    /// Full accumulated text from all deltas seen so far.
    text:               String,
    /// Events buffered in the lookahead window: (event, delta_text, text_end_offset).
    pending:            Vec<(SseEvent, String, usize)>,
    /// Byte offset in `text` up to which events have already been forwarded.
    forwarded_text_end: usize,
}

impl SseRedactBuffer {
    pub fn new() -> Self {
        SseRedactBuffer {
            text:               String::new(),
            pending:            Vec::new(),
            forwarded_text_end: 0,
        }
    }

    /// Push one parsed SSE event.
    ///
    /// Extracts the text delta (if any), appends it to the accumulated text,
    /// and returns any events that are now safe to forward (clear of the
    /// lookahead window and not part of a pending PII scan).
    pub fn push(&mut self, event: SseEvent, kind: UpstreamKind) -> Vec<SseEvent> {
        let delta = match kind {
            UpstreamKind::OpenAI    => openai_chunk_text(&event).unwrap_or_default(),
            UpstreamKind::Anthropic => anthropic_chunk_text(&event).unwrap_or_default(),
        };
        let text_end = self.text.len() + delta.len();
        self.text.push_str(&delta);
        self.pending.push((event, delta, text_end));
        self.drain_safe_window()
    }

    /// Called when `[DONE]` is received: scan and optionally redact the buffered
    /// tail, then return all remaining pending events for final forwarding.
    pub fn flush_done(&mut self) -> Vec<SseEvent> {
        if self.pending.is_empty() {
            return vec![];
        }
        let pending = std::mem::take(&mut self.pending);
        let tail = &self.text[self.forwarded_text_end..];
        if tail.is_empty() {
            return pending.into_iter().map(|(ev, _, _)| ev).collect();
        }
        // Scan the buffered tail for PII
        let detector = crate::detect::Detector::new();
        match detector.scan(tail) {
            crate::detect::DetectVerdict::Redact { redacted, .. } => {
                rebuild_events_redacted(pending, tail, &redacted)
            }
            crate::detect::DetectVerdict::Block { .. } => {
                // Tail contained block-level PII: replace with a single marker event
                vec![SseEvent {
                    event: None,
                    data:  "[TSM_BLOCKED: content removed by security policy]".into(),
                    id:    None,
                    retry: None,
                }]
            }
            _ => {
                // Clean: forward all buffered events unchanged
                pending.into_iter().map(|(ev, _, _)| ev).collect()
            }
        }
    }

    /// Drain events whose text ends before the lookahead window — these are
    /// safe to forward immediately without waiting for PII confirmation.
    fn drain_safe_window(&mut self) -> Vec<SseEvent> {
        let safe_up_to = self.text.len().saturating_sub(STREAM_LOOKAHEAD);
        let take = self.pending.iter()
            .take_while(|(_, _, end)| *end <= safe_up_to)
            .count();
        if take == 0 {
            return vec![];
        }
        let drained: Vec<_> = self.pending.drain(..take).collect();
        if let Some((_, _, end)) = drained.last() {
            self.forwarded_text_end = *end;
        }
        drained.into_iter().map(|(ev, _, _)| ev).collect()
    }
}

/// Rebuild buffered events, patching deltas that fall inside the redacted zone.
fn rebuild_events_redacted(
    pending:  Vec<(SseEvent, String, usize)>,
    original: &str,
    redacted: &str,
) -> Vec<SseEvent> {
    if original == redacted {
        return pending.into_iter().map(|(ev, _, _)| ev).collect();
    }
    // Find the first character position where original and redacted diverge.
    let diff_at = original
        .char_indices()
        .zip(redacted.char_indices())
        .find(|((_, a), (_, b))| a != b)
        .map(|((i, _), _)| i)
        .unwrap_or_else(|| original.len().min(redacted.len()));

    let mut out            = Vec::with_capacity(pending.len());
    let mut orig_cursor    = 0usize;
    let mut redacted_emitted = false;

    for (event, delta, _) in pending {
        let delta_start = orig_cursor;
        let delta_end   = orig_cursor + delta.len();
        orig_cursor     = delta_end;

        if delta_end <= diff_at {
            // Delta is entirely before the redaction zone — forward unchanged.
            out.push(event);
        } else if delta_start >= diff_at && !redacted_emitted {
            // First delta that overlaps the redaction zone: carry all redacted tail.
            redacted_emitted = true;
            let new_delta = redacted[diff_at..].to_owned();
            out.push(patch_event_delta(event, &delta, &new_delta));
        } else if delta_start >= diff_at {
            // Subsequent deltas after the redacted label was already emitted: empty.
            out.push(patch_event_delta(event, &delta, ""));
        } else {
            // Delta spans the diff boundary: safe prefix + redacted suffix.
            let safe_prefix = &delta[..diff_at.saturating_sub(delta_start)];
            let mut new_delta = safe_prefix.to_owned();
            if !redacted_emitted {
                redacted_emitted = true;
                new_delta.push_str(&redacted[diff_at..]);
            }
            out.push(patch_event_delta(event, &delta, &new_delta));
        }
    }
    out
}

/// Patch the text delta inside an SSE event's JSON payload.
///
/// Handles both OpenAI (`choices[0].delta.content`) and Anthropic (`delta.text`)
/// formats.  If neither is matched, the event is returned unchanged so the
/// stream is never broken.
fn patch_event_delta(event: SseEvent, old_delta: &str, new_delta: &str) -> SseEvent {
    if old_delta == new_delta {
        return event;
    }
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&event.data) {
        // OpenAI format: {"choices":[{"delta":{"content":"..."}},...]}
        if v["choices"][0]["delta"]["content"].is_string() {
            v["choices"][0]["delta"]["content"] = serde_json::Value::String(new_delta.into());
            if let Ok(new_data) = serde_json::to_string(&v) {
                return SseEvent { data: new_data, ..event };
            }
        }
        // Anthropic content_block_delta format: {"delta":{"text":"..."}}
        if v["delta"]["text"].is_string() {
            v["delta"]["text"] = serde_json::Value::String(new_delta.into());
            if let Ok(new_data) = serde_json::to_string(&v) {
                return SseEvent { data: new_data, ..event };
            }
        }
    }
    // Fallback: return unchanged rather than breaking the stream
    event
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
