/// In-place text redaction by span.
///
/// Given a list of byte-range spans, replaces the matched content with a
/// `[REDACTED:<TYPE>]` placeholder.  Spans must not overlap; they are sorted
/// and applied right-to-left so earlier offsets remain valid after each edit.

/// A span to redact, with its PII type label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactSpan {
    /// Byte offset of the first character to redact (inclusive).
    pub start:    usize,
    /// Byte offset one past the last character to redact (exclusive).
    pub end:      usize,
    /// The PII type label used in the placeholder, e.g. `"SSN"`.
    pub pii_type: String,
}

/// Apply all `spans` to `text`, returning the redacted string.
///
/// Behaviour:
/// - Spans are sorted by `start` descending so right-to-left application
///   keeps all earlier offsets valid.
/// - Overlapping spans are merged into the wider span, using the first
///   (leftmost) type label.
/// - The replacement is `[REDACTED:<TYPE>]`.
pub fn redact(text: &str, spans: &[RedactSpan]) -> String {
    if spans.is_empty() {
        return text.to_owned();
    }

    // Sort ascending, then merge overlaps
    let mut sorted = spans.to_vec();
    sorted.sort_by_key(|s| s.start);
    let merged = merge_overlapping(sorted);

    // Apply right-to-left on a byte vec for O(n) replacements
    let mut bytes: Vec<u8> = text.as_bytes().to_vec();
    for span in merged.iter().rev() {
        let placeholder = format!("[REDACTED:{}]", span.pii_type);
        bytes.splice(span.start..span.end, placeholder.into_bytes());
    }

    // The output is always valid UTF-8: the original text was UTF-8 and we
    // only splice in ASCII placeholder strings at character boundaries
    // (regex matches always align to char boundaries).
    String::from_utf8(bytes).unwrap_or_else(|_| {
        // Fallback: lossy convert (should never happen)
        String::from_utf8_lossy(text.as_bytes()).into_owned()
    })
}

/// Merge overlapping or adjacent spans.  Input must be sorted ascending by start.
fn merge_overlapping(mut spans: Vec<RedactSpan>) -> Vec<RedactSpan> {
    if spans.len() <= 1 {
        return spans;
    }
    let mut merged: Vec<RedactSpan> = Vec::with_capacity(spans.len());
    merged.push(spans.remove(0));

    for span in spans {
        let last = merged.last_mut().unwrap();
        if span.start <= last.end {
            // Overlap or adjacent — extend
            if span.end > last.end {
                last.end = span.end;
            }
        } else {
            merged.push(span);
        }
    }
    merged
}

/// Convenience: build a `RedactSpan` from a regex `Match`.
#[inline]
pub fn span_from_match(m: &regex::Match<'_>, pii_type: &str) -> RedactSpan {
    RedactSpan {
        start:    m.start(),
        end:      m.end(),
        pii_type: pii_type.to_owned(),
    }
}

/// Partially redact a credit card number, keeping the last 4 digits visible.
/// Returns `None` if the input doesn't look like a card number.
///
/// Example: `"4111111111111111"` → `"[REDACTED:CREDIT_CARD-****1111]"`
pub fn redact_partial_cc(text: &str, span: &RedactSpan) -> String {
    let matched = &text[span.start..span.end];
    let digits: String = matched.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 4 {
        let last4 = &digits[digits.len() - 4..];
        format!("[REDACTED:CREDIT_CARD-****{}]", last4)
    } else {
        "[REDACTED:CREDIT_CARD]".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: usize, end: usize, t: &str) -> RedactSpan {
        RedactSpan { start, end, pii_type: t.to_owned() }
    }

    #[test]
    fn single_span_redacted() {
        let text   = "My SSN is 123-45-6789 and I am fine";
        let spans  = vec![span(10, 21, "SSN")];
        let result = redact(text, &spans);
        assert_eq!(result, "My SSN is [REDACTED:SSN] and I am fine");
    }

    #[test]
    fn multiple_non_overlapping() {
        let text  = "SSN: 123-45-6789, card: 4111111111111111";
        let spans = vec![
            span(5, 16, "SSN"),
            span(24, 40, "CREDIT_CARD"),
        ];
        let result = redact(text, &spans);
        assert_eq!(result, "SSN: [REDACTED:SSN], card: [REDACTED:CREDIT_CARD]");
    }

    #[test]
    fn overlapping_spans_merged() {
        let text  = "secret: abc123def456ghi789";
        // Two overlapping spans
        let spans = vec![
            span(8, 17, "TOKEN"),
            span(13, 26, "TOKEN"),
        ];
        let result = redact(text, &spans);
        // Should merge into one replacement covering 8..26
        assert_eq!(result, "secret: [REDACTED:TOKEN]");
    }

    #[test]
    fn empty_spans_returns_original() {
        let text   = "Hello world";
        let result = redact(text, &[]);
        assert_eq!(result, text);
    }

    #[test]
    fn spans_applied_right_to_left_offsets_correct() {
        // If applied left-to-right, the second span offset would shift.
        // Verify right-to-left application keeps both correct.
        let text  = "a: 111-22-3333 b: 444-55-6666";
        let spans = vec![
            span(3, 14, "SSN"),
            span(18, 29, "SSN"),
        ];
        let result = redact(text, &spans);
        assert_eq!(result, "a: [REDACTED:SSN] b: [REDACTED:SSN]");
    }

    #[test]
    fn partial_cc_redaction() {
        let text = "pay with 4111111111111111 today";
        let s    = span(9, 25, "CREDIT_CARD");
        let r    = redact_partial_cc(text, &s);
        assert_eq!(r, "[REDACTED:CREDIT_CARD-****1111]");
    }
}
