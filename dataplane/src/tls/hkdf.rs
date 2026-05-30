/// HKDF-Expand-Label as specified in RFC 8446 §7.1.
///
/// Uses `ring::hmac` for HMAC-SHA256 and `ring::digest` for SHA-256.
/// No external crate beyond `ring`.
///
/// HKDF-Expand-Label(Secret, Label, Context, Length):
///   HkdfLabel = Length ++ "tls13 " ++ Label ++ Context
///   OKM = HKDF-Expand(Secret, HkdfLabel, Length)
///
/// Where HKDF-Expand is built from repeated HMAC applications.

use ring::hmac;

// ── HKDF-Extract ─────────────────────────────────────────────────────────────

/// HKDF-Extract(salt, ikm) → PRK  (RFC 5869 §2.2)
/// When salt is omitted (empty), uses a string of HashLen zero bytes.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt_key = if salt.is_empty() {
        hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32])
    } else {
        hmac::Key::new(hmac::HMAC_SHA256, salt)
    };
    let tag = hmac::sign(&salt_key, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

// ── HKDF-Expand ──────────────────────────────────────────────────────────────

/// HKDF-Expand(PRK, info, L) → OKM  (RFC 5869 §2.3)
/// Output length `length` must be ≤ 255 * HashLen (32) = 8160 bytes.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    assert!(length <= 255 * 32, "HKDF-Expand: length exceeds 255 * HashLen");
    let prk_key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut okm:  Vec<u8> = Vec::with_capacity(length + 32);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8   = 1;

    while okm.len() < length {
        let mut ctx = hmac::Context::with_key(&prk_key);
        ctx.update(&prev);
        ctx.update(info);
        ctx.update(&[counter]);
        let tag = ctx.sign();
        prev = tag.as_ref().to_vec();
        okm.extend_from_slice(&prev);
        counter += 1;
    }

    okm.truncate(length);
    okm
}

// ── HKDF-Expand-Label ─────────────────────────────────────────────────────────

/// HKDF-Expand-Label(Secret, Label, Context, Length)  (RFC 8446 §7.1)
///
/// HkdfLabel structure (encoded as bytes):
///   uint16 length
///   opaque label<7..255>  = "tls13 " + Label
///   opaque context<0..255>
pub fn hkdf_expand_label(
    secret:  &[u8; 32],
    label:   &str,
    context: &[u8],
    length:  usize,
) -> Vec<u8> {
    let full_label = format!("tls13 {}", label);
    let label_bytes = full_label.as_bytes();

    // Build HkdfLabel
    let mut info = Vec::with_capacity(2 + 1 + label_bytes.len() + 1 + context.len());
    // Length (u16 big-endian)
    info.push((length >> 8) as u8);
    info.push(length as u8);
    // Label length + label
    info.push(label_bytes.len() as u8);
    info.extend_from_slice(label_bytes);
    // Context length + context
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    hkdf_expand(secret, &info, length)
}

// ── Derive-Secret ─────────────────────────────────────────────────────────────

/// Derive-Secret(Secret, Label, Messages)  (RFC 8446 §7.1)
/// Messages = transcript hash (SHA-256 of handshake messages so far).
pub fn derive_secret(secret: &[u8; 32], label: &str, transcript_hash: &[u8; 32]) -> [u8; 32] {
    let okm = hkdf_expand_label(secret, label, transcript_hash, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    out
}

// ── Zero ──────────────────────────────────────────────────────────────────────

/// All-zeros IKM used at the start of the TLS 1.3 key schedule.
pub const ZEROS_32: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Test Case 1 (HMAC-SHA256)
    #[test]
    fn hkdf_test_vector_rfc5869_case1() {
        let ikm  = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        let prk = hkdf_extract(&salt, &ikm);
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn expand_label_length_correct() {
        let secret = [0u8; 32];
        let okm    = hkdf_expand_label(&secret, "key", &[], 16);
        assert_eq!(okm.len(), 16);
    }

    #[test]
    fn expand_label_different_labels_different_output() {
        let secret = [42u8; 32];
        let key_a  = hkdf_expand_label(&secret, "key", &[], 32);
        let key_b  = hkdf_expand_label(&secret, "iv",  &[], 32);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn derive_secret_deterministic() {
        let secret = [1u8; 32];
        let hash   = [2u8; 32];
        let a = derive_secret(&secret, "handshake traffic secret", &hash);
        let b = derive_secret(&secret, "handshake traffic secret", &hash);
        assert_eq!(a, b);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
