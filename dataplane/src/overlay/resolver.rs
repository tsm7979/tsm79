//! Sovereign-overlay name resolver — the registry that replaces ICANN/DNS.
//!
//! Records are self-authenticating (each carries the owner's Ed25519 signature),
//! so the registry only needs to enforce three invariants:
//!   1. signatures verify  (no forged bindings),
//!   2. a name can only ever be rebound by its ORIGINAL key (no hijack/squat),
//!   3. updates strictly increase `sequence` (no replay/rollback).
//!
//! This in-process registry is the LOCAL view. A future phase replaces the map
//! with a Kademlia DHT so the same signed records propagate across the P2P mesh
//! — the verification rules here are identical either way, which is the whole
//! point of self-certifying names.

use std::collections::HashMap;
use std::sync::RwLock;

use super::name::{NameError, NameRecord};

/// Thread-safe registry of verified name → record bindings.
pub struct Resolver {
    records: RwLock<HashMap<String, NameRecord>>,
}

impl Resolver {
    pub fn new() -> Self {
        Resolver { records: RwLock::new(HashMap::new()) }
    }

    /// Publish or update a signed binding. Rejects forged signatures, hijack
    /// attempts (rebinding to a different key), and stale/replayed updates.
    pub fn publish(&self, rec: NameRecord) -> Result<(), NameError> {
        if !rec.verify() {
            return Err(NameError::InvalidSignature);
        }
        let mut map = self.records.write().expect("resolver lock poisoned");
        if let Some(existing) = map.get(&rec.name) {
            if existing.pubkey != rec.pubkey {
                return Err(NameError::NameHijack);
            }
            if rec.sequence <= existing.sequence {
                return Err(NameError::StaleSequence);
            }
        }
        map.insert(rec.name.clone(), rec);
        Ok(())
    }

    /// Resolve a name to its current (already-verified) record.
    pub fn resolve(&self, name: &str) -> Option<NameRecord> {
        self.records
            .read()
            .expect("resolver lock poisoned")
            .get(name)
            .cloned()
    }

    /// Number of names currently registered.
    pub fn len(&self) -> usize {
        self.records.read().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::Ed25519KeyPair;

    fn keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()
    }

    #[test]
    fn publish_then_resolve() {
        let r  = Resolver::new();
        let kp = keypair();
        let rec = NameRecord::create("hub.tsm", "https://10.0.0.1:443", 1, &kp);
        assert!(r.publish(rec.clone()).is_ok());
        let got = r.resolve("hub.tsm").expect("resolvable");
        assert_eq!(got.endpoint, "https://10.0.0.1:443");
        assert!(r.resolve("missing.tsm").is_none());
    }

    #[test]
    fn forged_record_rejected() {
        let r = Resolver::new();
        let kp = keypair();
        let mut rec = NameRecord::create("hub.tsm", "https://10.0.0.1:443", 1, &kp);
        rec.endpoint = "https://evil:443".to_owned(); // breaks signature
        assert_eq!(r.publish(rec), Err(NameError::InvalidSignature));
    }

    #[test]
    fn hijack_rejected() {
        let r = Resolver::new();
        let owner    = keypair();
        let attacker = keypair();
        r.publish(NameRecord::create("hub.tsm", "https://owner:443", 1, &owner)).unwrap();
        // Attacker validly signs a record for the SAME name with their own key.
        let evil = NameRecord::create("hub.tsm", "https://attacker:443", 2, &attacker);
        assert_eq!(r.publish(evil), Err(NameError::NameHijack));
        // Original binding is untouched.
        assert_eq!(r.resolve("hub.tsm").unwrap().endpoint, "https://owner:443");
    }

    #[test]
    fn stale_update_rejected_owner_update_accepted() {
        let r = Resolver::new();
        let kp = keypair();
        r.publish(NameRecord::create("hub.tsm", "https://v1:443", 5, &kp)).unwrap();
        // Replay / rollback with <= sequence is rejected.
        assert_eq!(
            r.publish(NameRecord::create("hub.tsm", "https://old:443", 5, &kp)),
            Err(NameError::StaleSequence)
        );
        // Genuine owner update with a higher sequence wins.
        assert!(r.publish(NameRecord::create("hub.tsm", "https://v2:443", 6, &kp)).is_ok());
        assert_eq!(r.resolve("hub.tsm").unwrap().endpoint, "https://v2:443");
    }
}
