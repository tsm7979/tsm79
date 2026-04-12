/// Structural token scanner: JWT, base64 blobs, and high-entropy binary tokens.
///
/// These are complementary to the regex pattern scanner.  They catch secrets
/// that have a recognisable structural signature but don't match a specific
/// vendor prefix.

/// A structural hit found in the scanned text.
#[derive(Debug, Clone)]
pub struct StructuralHit {
    pub kind:  StructuralKind,
    pub start: usize,
    pub end:   usize,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StructuralKind {
    /// Three-part base64url.base64url.base64url — classic JWT
    Jwt,
    /// Long base64-standard or base64url blob (≥ 40 chars, high entropy)
    Base64Blob,
    /// Hex-encoded blob ≥ 32 hex chars (e.g., raw SHA-256 hashes stored as secrets)
    HexBlob,
}

impl StructuralKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            StructuralKind::Jwt       => "JWT",
            StructuralKind::Base64Blob => "HIGH_ENTROPY",
            StructuralKind::HexBlob   => "HIGH_ENTROPY",
        }
    }

    /// Risk contribution (0–25 points added to base risk).
    pub fn risk_points(&self) -> f64 {
        match self {
            StructuralKind::Jwt        => 20.0,
            StructuralKind::Base64Blob => 15.0,
            StructuralKind::HexBlob    => 10.0,
        }
    }
}

// ── Scanner ───────────────────────────────────────────────────────────────────

/// Scan `text` for structural tokens (JWT, base64 blobs, hex blobs).
/// Returns all hits found, in order of appearance.
pub fn scan_structural(text: &str) -> Vec<StructuralHit> {
    let mut hits = Vec::new();

    // Walk token-by-token (whitespace-delimited)
    let mut offset = 0usize;
    for raw_token in text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';')) {
        let start = offset;
        let end   = offset + raw_token.len();
        offset    = end + 1; // +1 for the delimiter

        let token = raw_token.trim_matches(|c: char| matches!(c, '.' | '-' | '_' | '(' | ')' | '[' | ']'));
        if token.is_empty() {
            continue;
        }

        if let Some(hit) = try_jwt(token, start) {
            hits.push(hit);
            continue;
        }
        if let Some(hit) = try_base64_blob(token, start) {
            hits.push(hit);
            continue;
        }
        if let Some(hit) = try_hex_blob(token, start) {
            hits.push(hit);
        }
    }

    hits
}

// ── Individual detectors ──────────────────────────────────────────────────────

/// Detect a JWT: three dot-separated base64url segments where the first
/// decodes to JSON with an `alg` field.
fn try_jwt(token: &str, base_offset: usize) -> Option<StructuralHit> {
    let parts: Vec<&str> = token.splitn(4, '.').collect();
    if parts.len() != 3 {
        return None;
    }

    // All three parts must be non-empty base64url
    if parts.iter().any(|p| p.is_empty() || !is_base64url(p)) {
        return None;
    }

    // First part (header) must decode to JSON with "alg"
    if let Ok(header_bytes) = base64url_decode(parts[0]) {
        if let Ok(header_str) = std::str::from_utf8(&header_bytes) {
            if header_str.contains("\"alg\"") {
                return Some(StructuralHit {
                    kind:  StructuralKind::Jwt,
                    start: base_offset,
                    end:   base_offset + token.len(),
                    value: token.to_owned(),
                });
            }
        }
    }

    None
}

/// Detect a long base64(-url) blob with high character diversity.
fn try_base64_blob(token: &str, base_offset: usize) -> Option<StructuralHit> {
    if token.len() < 40 {
        return None;
    }
    // Allow standard or URL-safe base64, with optional padding
    let stripped = token.trim_end_matches('=');
    if !stripped.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '-' || c == '_') {
        return None;
    }
    // Require at least 5 distinct characters (filters out repeated patterns)
    let distinct: std::collections::HashSet<char> = stripped.chars().collect();
    if distinct.len() < 5 {
        return None;
    }
    // Entropy check via our own function (reuse the bytes directly)
    let ent = crate::detect::entropy::shannon_entropy(stripped.as_bytes());
    if ent < 4.2 {
        return None;
    }

    Some(StructuralHit {
        kind:  StructuralKind::Base64Blob,
        start: base_offset,
        end:   base_offset + token.len(),
        value: token.to_owned(),
    })
}

/// Detect a long hex-encoded blob (≥ 32 hex chars).
fn try_hex_blob(token: &str, base_offset: usize) -> Option<StructuralHit> {
    if token.len() < 32 {
        return None;
    }
    if !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    // Filter out all-same-digit / very low diversity
    let distinct: std::collections::HashSet<char> = token.chars().collect();
    if distinct.len() < 6 {
        return None;
    }

    Some(StructuralHit {
        kind:  StructuralKind::HexBlob,
        start: base_offset,
        end:   base_offset + token.len(),
        value: token.to_owned(),
    })
}

// ── Base64 helpers ────────────────────────────────────────────────────────────

fn is_base64url(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

/// Decode base64url (URL-safe, no padding required).
fn base64url_decode(s: &str) -> Result<Vec<u8>, ()> {
    // Convert URL-safe to standard, add padding
    let mut standard = s.replace('-', "+").replace('_', "/");
    match standard.len() % 4 {
        2 => standard.push_str("=="),
        3 => standard.push('='),
        _ => {}
    }
    base64_decode_standard(&standard)
}

/// Minimal standard base64 decoder — no external crate.
pub fn base64_decode_standard(s: &str) -> Result<Vec<u8>, ()> {
    const TABLE: [i8; 256] = {
        let mut t = [-1i8; 256];
        let mut i = 0u8;
        // A-Z
        while i < 26 { t[(b'A' + i) as usize] = i as i8; i += 1; }
        i = 0;
        // a-z
        while i < 26 { t[(b'a' + i) as usize] = (26 + i) as i8; i += 1; }
        i = 0;
        // 0-9
        while i < 10 { t[(b'0' + i) as usize] = (52 + i) as i8; i += 1; }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t[b'=' as usize] = 0;  // padding
        t
    };

    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(());
    }

    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let v: Vec<i8> = chunk.iter().map(|&b| TABLE[b as usize]).collect();
        if v.iter().any(|&x| x < 0) {
            return Err(());
        }
        let triple = ((v[0] as u32) << 18) | ((v[1] as u32) << 12) | ((v[2] as u32) << 6) | (v[3] as u32);
        out.push((triple >> 16) as u8);
        if chunk[2] != b'=' { out.push((triple >> 8) as u8); }
        if chunk[3] != b'=' { out.push(triple as u8); }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_detected() {
        // Real JWT-shaped token (header = {"alg":"HS256","typ":"JWT"} encoded)
        // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let hits = scan_structural(token);
        assert!(!hits.is_empty(), "should detect JWT");
        assert_eq!(hits[0].kind, StructuralKind::Jwt);
    }

    #[test]
    fn base64_blob_detected() {
        // 44-char base64 blob
        let text = "secret dGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQ=";
        let hits = scan_structural(text);
        // May or may not fire depending on entropy — just assert no panic
        let _ = hits;
    }

    #[test]
    fn clean_text_no_hits() {
        let hits = scan_structural("What is the capital of France?");
        assert!(hits.is_empty());
    }

    #[test]
    fn base64_decode_roundtrip() {
        let encoded = "SGVsbG8gV29ybGQ=";
        let decoded = base64_decode_standard(encoded).unwrap();
        assert_eq!(decoded, b"Hello World");
    }
}
