//! Self-certifying overlay names — the `.tsm` namespace.
//!
//! No ICANN, no registrar, no fees. A name is bound to an Ed25519 public key by
//! a SIGNED record: only the holder of the private key can publish or update the
//! binding, and anyone can verify it offline. A *self-certifying* address is the
//! base32 of the public key itself (the model Tor v3 `.onion` uses) — so the
//! name literally IS the key, and proving possession of the key proves ownership.
//!
//! Uses Ed25519 from the existing `ring` dependency (no new crates).

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

/// Overlay namespace suffix.
pub const TSM_TLD: &str = ".tsm";

/// Reasons a name publish/update can be rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// The record's signature does not verify against its embedded public key.
    InvalidSignature,
    /// Attempt to rebind an existing name to a DIFFERENT key (squat/hijack).
    NameHijack,
    /// Update carries a non-increasing sequence (stale or replayed).
    StaleSequence,
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NameError::InvalidSignature => "invalid signature",
            NameError::NameHijack       => "name already bound to a different key",
            NameError::StaleSequence    => "stale or replayed sequence",
        };
        f.write_str(s)
    }
}

/// A signed binding: name → owner public key → routing endpoint.
///
/// `sequence` allows the owner to publish updates (higher wins); the signature
/// covers every field, so no part can be tampered with after signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRecord {
    pub name:      String,
    pub pubkey:    [u8; 32],
    pub endpoint:  String,
    pub sequence:  u64,
    pub signature: [u8; 64],
}

impl NameRecord {
    /// Canonical, domain-separated bytes that the signature covers.
    fn signing_bytes(name: &str, pubkey: &[u8; 32], endpoint: &str, sequence: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(64 + name.len() + endpoint.len());
        v.extend_from_slice(b"tsm-overlay-name-v1");
        v.push(0);
        v.extend_from_slice(name.as_bytes());
        v.push(0);
        v.extend_from_slice(pubkey);
        v.push(0);
        v.extend_from_slice(endpoint.as_bytes());
        v.push(0);
        v.extend_from_slice(&sequence.to_be_bytes());
        v
    }

    /// Create a signed record with the owner's keypair.
    pub fn create(name: &str, endpoint: &str, sequence: u64, kp: &Ed25519KeyPair) -> NameRecord {
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(kp.public_key().as_ref());
        let msg = Self::signing_bytes(name, &pubkey, endpoint, sequence);
        let sig = kp.sign(&msg);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(sig.as_ref());
        NameRecord {
            name: name.to_owned(),
            pubkey,
            endpoint: endpoint.to_owned(),
            sequence,
            signature,
        }
    }

    /// Verify the signature cryptographically binds (name, pubkey, endpoint, seq).
    pub fn verify(&self) -> bool {
        let msg = Self::signing_bytes(&self.name, &self.pubkey, &self.endpoint, self.sequence);
        UnparsedPublicKey::new(&ED25519, &self.pubkey)
            .verify(&msg, &self.signature)
            .is_ok()
    }

    /// True when the name is the self-certifying base32 of its own key
    /// (i.e. `<base32(pubkey)>.tsm`) — ownership is then intrinsic to the name.
    pub fn is_self_certifying(&self) -> bool {
        derive_address(&self.pubkey) == self.name
    }

    /// Lowercase hex of the public key (for display / audit).
    pub fn pubkey_hex(&self) -> String {
        self.pubkey.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Derive the self-certifying address `<base32(pubkey)>.tsm` for a public key.
pub fn derive_address(pubkey: &[u8; 32]) -> String {
    format!("{}{}", base32_encode(pubkey), TSM_TLD)
}

/// RFC 4648 base32 (lowercase, no padding). 32 bytes → 52 chars.
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in data {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((bits >> nbits) & 31) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPHABET[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).expect("pkcs8");
        Ed25519KeyPair::from_pkcs8(doc.as_ref()).expect("keypair")
    }

    #[test]
    fn signed_record_verifies() {
        let kp = keypair();
        let rec = NameRecord::create("hub.tsm", "https://10.0.0.1:443", 1, &kp);
        assert!(rec.verify(), "freshly signed record must verify");
    }

    #[test]
    fn tampered_record_fails() {
        let kp = keypair();
        let mut rec = NameRecord::create("hub.tsm", "https://10.0.0.1:443", 1, &kp);
        rec.endpoint = "https://evil.example:443".to_owned(); // tamper after signing
        assert!(!rec.verify(), "tampered endpoint must break the signature");
    }

    #[test]
    fn wrong_key_cannot_forge() {
        let owner   = keypair();
        let attacker = keypair();
        let mut rec = NameRecord::create("hub.tsm", "https://10.0.0.1:443", 1, &owner);
        // Attacker swaps in their own pubkey but keeps the owner's signature.
        rec.pubkey.copy_from_slice(attacker.public_key().as_ref());
        assert!(!rec.verify(), "signature must not verify under a different key");
    }

    #[test]
    fn self_certifying_address_roundtrips() {
        let kp = keypair();
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(kp.public_key().as_ref());
        let addr = derive_address(&pubkey);
        assert!(addr.ends_with(".tsm"));
        assert_eq!(addr.len() - TSM_TLD.len(), 52, "32-byte key → 52 base32 chars");

        let rec = NameRecord::create(&addr, "https://10.0.0.1:443", 1, &kp);
        assert!(rec.is_self_certifying(), "name derived from key must be self-certifying");
    }

    #[test]
    fn base32_is_lowercase_alphanumeric() {
        let s = base32_encode(&[0xff; 32]);
        assert!(s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }
}
