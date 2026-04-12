/// Shannon entropy scanner.
///
/// Used to detect high-entropy strings that are likely secrets
/// (API keys, tokens, private keys) even when they don't match a known pattern.
///
/// Formula: H = -∑ p(x) * log2(p(x))
/// A perfectly random 32-byte key has entropy ≈ 6.0 bits/char.
/// English prose typically scores 3.5–4.5 bits/char.

/// Compute the Shannon entropy of a byte slice in bits per character.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// A contiguous token extracted from text that may be a high-entropy secret.
#[derive(Debug, Clone)]
pub struct EntropyHit {
    pub token:   String,
    pub start:   usize,
    pub end:     usize,
    pub entropy: f64,
}

/// Scan `text` for tokens that exceed `threshold` bits/char entropy.
///
/// Tokens are runs of non-whitespace, non-quote, non-bracket characters
/// with a minimum length of `min_len` bytes.  Thresholds:
///   - ≥ 4.5 bits/char AND len ≥ 20 → candidate
///   - ≥ 5.0 bits/char AND len ≥ 16 → strong candidate
///   - ≥ 5.5 bits/char AND len ≥ 12 → very strong candidate
pub fn scan_entropy(text: &str, threshold: f64, min_len: usize) -> Vec<EntropyHit> {
    let mut hits = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Skip delimiters: whitespace, quotes, brackets, colons, commas
        if is_delimiter(bytes[i]) {
            i += 1;
            continue;
        }

        // Collect a token
        let start = i;
        while i < bytes.len() && !is_delimiter(bytes[i]) {
            i += 1;
        }
        let end = i;
        let token_bytes = &bytes[start..end];

        if token_bytes.len() < min_len {
            continue;
        }

        // Strip common surrounding punctuation that isn't part of the secret
        let token_bytes = strip_surrounding_punct(token_bytes);
        if token_bytes.len() < min_len {
            continue;
        }

        let ent = shannon_entropy(token_bytes);
        if ent >= threshold {
            // Safety: the original text is valid UTF-8; our token is a slice
            // of its bytes at character boundaries (all delimiters are ASCII).
            let token_str = String::from_utf8_lossy(token_bytes).into_owned();
            hits.push(EntropyHit {
                token: token_str,
                start,
                end,
                entropy: ent,
            });
        }
    }

    hits
}

fn is_delimiter(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r'
               | b'"' | b'\'' | b'`'
               | b'(' | b')' | b'[' | b']' | b'{' | b'}'
               | b',' | b';' | b':' | b'<' | b'>')
}

fn strip_surrounding_punct(b: &[u8]) -> &[u8] {
    let lo = b.iter().position(|&c| !matches!(c, b'.' | b'-' | b'_' | b'/')).unwrap_or(0);
    let hi = b.iter().rposition(|&c| !matches!(c, b'.' | b'-' | b'_' | b'/')).map(|p| p + 1).unwrap_or(b.len());
    if lo < hi { &b[lo..hi] } else { b }
}

/// Composite entropy verdict for a scanned text.
#[derive(Debug, Clone)]
pub struct EntropyVerdict {
    /// Whether any token exceeded the high-entropy threshold.
    pub high_entropy_found: bool,
    /// The highest entropy score observed across all tokens.
    pub max_entropy: f64,
    /// How much this adds to the overall risk score (0–30 points).
    pub risk_contribution: f64,
    /// The token with the highest entropy, if any.
    pub top_token: Option<String>,
}

/// Scan and produce a structured verdict used by the main detector.
pub fn entropy_verdict(text: &str) -> EntropyVerdict {
    // Two tiers: moderate (4.5, len≥20) and strong (5.0, len≥16)
    let strong_hits   = scan_entropy(text, 5.0, 16);
    let moderate_hits = scan_entropy(text, 4.5, 20);

    let all_hits: Vec<&EntropyHit> = strong_hits.iter().chain(moderate_hits.iter()).collect();

    if all_hits.is_empty() {
        return EntropyVerdict {
            high_entropy_found: false,
            max_entropy: 0.0,
            risk_contribution: 0.0,
            top_token: None,
        };
    }

    let top = all_hits.iter().max_by(|a, b| a.entropy.partial_cmp(&b.entropy).unwrap()).unwrap();
    let max_ent = top.entropy;

    // Risk contribution: scale from 0 to 30 between 4.5 and 6.5 bits/char
    let contribution = ((max_ent - 4.5) / 2.0 * 30.0).clamp(0.0, 30.0);

    EntropyVerdict {
        high_entropy_found: true,
        max_entropy:        max_ent,
        risk_contribution:  contribution,
        top_token:          Some(top.token.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_zero_entropy() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn single_char_has_zero_entropy() {
        assert_eq!(shannon_entropy(b"aaaaaaa"), 0.0);
    }

    #[test]
    fn uniform_distribution_max_entropy() {
        // 256 distinct bytes → entropy approaches log2(256) = 8.0
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let ent = shannon_entropy(&all_bytes);
        assert!((ent - 8.0).abs() < 0.01, "got {}", ent);
    }

    #[test]
    fn prose_low_entropy() {
        let prose = b"The quick brown fox jumps over the lazy dog";
        let ent = shannon_entropy(prose);
        // English prose typically 3.5–4.5 bits
        assert!(ent < 5.0, "prose entropy too high: {}", ent);
    }

    #[test]
    fn api_key_high_entropy() {
        // Simulate a 40-char random alphanumeric token
        let key = b"aB3dEf7gHi2jKl9mNoPqRs4tUvWxYz1A2B3C4D5E";
        let ent = shannon_entropy(key);
        assert!(ent > 4.5, "key entropy too low: {}", ent);
    }

    #[test]
    fn scan_finds_high_entropy_token() {
        let text = "Authorization: Bearer aB3dEf7gHi2jKl9mNoPqRs4tUvWxYz1A2B3C4D5E";
        let hits = scan_entropy(text, 4.5, 16);
        assert!(!hits.is_empty(), "should find the token");
    }

    #[test]
    fn entropy_verdict_on_clean_text() {
        let v = entropy_verdict("What is the capital of France?");
        assert!(!v.high_entropy_found);
        assert_eq!(v.risk_contribution, 0.0);
    }
}
