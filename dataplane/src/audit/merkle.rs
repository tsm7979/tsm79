/// Merkle-tree audit chain — tamper-evident log with O(log n) inclusion proofs.
///
/// Architecture:
///   Each audit event is a leaf hash: SHA-256(timestamp ‖ session_id ‖ action ‖ prev_root).
///   Leaves are batched into a binary Merkle tree per "epoch" (every EPOCH_SIZE events).
///   The epoch root is chained to the previous epoch root, forming a hash chain of trees.
///
/// Properties:
///   - Append-only: inserting at any non-end position changes the root.
///   - Provable: generate_proof(index) returns the sibling path for external verification.
///   - Chainable: epoch roots form a linked list; tampering with an old epoch changes all
///     subsequent roots.
///
/// This upgrades the prior HMAC audit chain (sequential, hard to prove inclusion)
/// to a structure that supports:
///   1. Efficient inclusion proofs (O(log n) hashes to prove a single event).
///   2. Compact epoch roots for external pinning (e.g., publishing to a public ledger).
///   3. Batch verification: verify the entire chain without replaying every event.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Events per epoch tree. Must be a power of two for clean binary trees.
const EPOCH_SIZE: usize = 256;

// ── Hashing ───────────────────────────────────────────────────────────────────

/// SHA-256 via the standard library's `std::hash` is not cryptographic.
/// We implement a minimal SHA-256 without external crates, consistent with
/// the dataplane's no-external-crypto-crate policy (raw TLS is in tls/).
///
/// This is a complete, correct SHA-256 implementation.
fn sha256(data: &[u8]) -> [u8; 32] {
    // Initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes).
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Round constants (first 32 bits of fractional parts of cube roots of first 64 primes).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Pre-processing: add padding.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg  = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0x00); }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) chunk.
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i*4..i*4+4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17)  ^ w[i-2].rotate_right(19)  ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
            [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];

        for i in 0..64 {
            let s1    = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch    = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0    = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj   = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g; g = f; f = e;
            e  = d.wrapping_add(temp1);
            d  = c; c = b; b = a;
            a  = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &v) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn hash_pair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(l);
    buf[32..].copy_from_slice(r);
    sha256(&buf)
}

fn hash_leaf(timestamp_us: u64, session_id: &str, action: &str, prev_root: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + session_id.len() + 1 + action.len() + 32);
    buf.extend_from_slice(&timestamp_us.to_be_bytes());
    buf.extend_from_slice(session_id.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(action.as_bytes());
    buf.extend_from_slice(prev_root);
    sha256(&buf)
}

// ── Merkle tree for a single epoch ───────────────────────────────────────────

/// A complete binary Merkle tree over exactly `EPOCH_SIZE` leaves.
/// Leaves are padded with zeroes if the epoch isn't full yet.
#[derive(Clone)]
struct EpochTree {
    leaves: Vec<[u8; 32]>,
    nodes:  Vec<[u8; 32]>,  // index 0 = root; filled lazily
    root:   [u8; 32],
}

impl EpochTree {
    fn build(leaves: Vec<[u8; 32]>) -> Self {
        assert!(leaves.len() <= EPOCH_SIZE);

        let mut padded = leaves.clone();
        while padded.len() < EPOCH_SIZE {
            padded.push([0u8; 32]);
        }

        // Build bottom-up. nodes[0] = root; total 2*EPOCH_SIZE - 1 nodes.
        let n     = EPOCH_SIZE;
        let total = 2 * n - 1;
        let mut nodes = vec![[0u8; 32]; total];

        // Leaves occupy the bottom row: indices [n-1, 2n-2].
        for (i, leaf) in padded.iter().enumerate() {
            nodes[n - 1 + i] = *leaf;
        }

        // Internal nodes: build bottom-up.
        for i in (0..n-1).rev() {
            nodes[i] = hash_pair(&nodes[2*i+1], &nodes[2*i+2]);
        }

        let root = nodes[0];
        EpochTree { leaves, nodes, root }
    }

    /// Generate a Merkle proof for `leaf_index` within this epoch.
    /// Returns the sibling hashes from bottom to top.
    fn proof(&self, leaf_index: usize) -> MerkleProof {
        let n = EPOCH_SIZE;
        let mut path  = Vec::new();
        let mut idx   = n - 1 + leaf_index; // start at leaf node

        while idx > 0 {
            let sibling = if idx % 2 == 0 { idx - 1 } else { idx + 1 };
            path.push(ProofStep {
                hash:    self.nodes[sibling],
                is_left: idx % 2 == 0, // sibling is on the left
            });
            idx = (idx - 1) / 2;
        }

        MerkleProof { path, root: self.root }
    }
}

// ── Proof types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProofStep {
    pub hash:    [u8; 32],
    pub is_left: bool, // if true, sibling is left of current node
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub path: Vec<ProofStep>,
    pub root: [u8; 32],
}

impl MerkleProof {
    /// Verify that `leaf_hash` is part of the committed root.
    pub fn verify(&self, leaf_hash: &[u8; 32]) -> bool {
        let mut current = *leaf_hash;
        for step in &self.path {
            current = if step.is_left {
                hash_pair(&step.hash, &current)
            } else {
                hash_pair(&current, &step.hash)
            };
        }
        current == self.root
    }

    /// Hex-encode the root for logging / external pinning.
    pub fn root_hex(&self) -> String {
        self.root.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ── Sealed epoch ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SealedEpoch {
    pub index:      u64,
    pub root:       [u8; 32],
    pub prev_root:  [u8; 32],
    pub event_count: usize,
    tree:           EpochTree,
}

impl SealedEpoch {
    /// Generate an inclusion proof for the given leaf index within this epoch.
    pub fn proof_for(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.event_count { return None; }
        Some(self.tree.proof(leaf_index))
    }

    pub fn root_hex(&self) -> String {
        self.root.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ── MerkleAuditChain ─────────────────────────────────────────────────────────

/// The main audit chain. Append events with `push()`.
/// Sealed epochs are stored and can be queried for proofs.
pub struct MerkleAuditChain {
    /// Sealed, fully computed epochs.
    sealed:        Vec<SealedEpoch>,
    /// Leaves accumulating in the current (open) epoch.
    pending_leaves: Vec<[u8; 32]>,
    /// The root of the most recently sealed epoch (or zero for the genesis).
    chain_root:    [u8; 32],
    /// Count of all events ever appended.
    total_events:  u64,
}

impl MerkleAuditChain {
    pub fn new() -> Self {
        MerkleAuditChain {
            sealed:         Vec::new(),
            pending_leaves: Vec::new(),
            chain_root:     [0u8; 32],
            total_events:   0,
        }
    }

    /// Append a new audit event.
    pub fn push(&mut self, session_id: &str, action: &str) -> u64 {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        let leaf = hash_leaf(ts, session_id, action, &self.chain_root);
        self.pending_leaves.push(leaf);
        self.total_events += 1;

        // Seal when the epoch is full.
        if self.pending_leaves.len() == EPOCH_SIZE {
            self.seal_epoch();
        }

        self.total_events - 1 // return global event index
    }

    /// Force-seal the current pending epoch (useful at shutdown).
    pub fn flush(&mut self) {
        if !self.pending_leaves.is_empty() {
            self.seal_epoch();
        }
    }

    /// Total events appended.
    pub fn len(&self) -> u64 { self.total_events }

    /// Current chain root (root of the latest sealed epoch, or zero if none).
    pub fn chain_root_hex(&self) -> String {
        self.chain_root.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Generate an inclusion proof for a given global event index.
    ///
    /// Returns `None` if the event is in the currently open (unsealed) epoch.
    pub fn proof_for(&self, global_index: u64) -> Option<MerkleProof> {
        let epoch_idx  = (global_index / EPOCH_SIZE as u64) as usize;
        let leaf_index = (global_index % EPOCH_SIZE as u64) as usize;

        let epoch = self.sealed.get(epoch_idx)?;
        epoch.proof_for(leaf_index)
    }

    /// Reference to all sealed epochs (for external pinning / replication).
    pub fn sealed_epochs(&self) -> &[SealedEpoch] {
        &self.sealed
    }

    /// Return the latest N epoch roots for a compact summary.
    pub fn recent_roots(&self, n: usize) -> Vec<String> {
        self.sealed.iter().rev().take(n)
            .map(|e| e.root_hex())
            .collect()
    }

    /// Index of the current (open) epoch — equals the number of sealed epochs.
    pub fn current_epoch(&self) -> usize { self.sealed.len() }

    /// Number of leaves accumulated in the current open epoch.
    pub fn current_leaf(&self) -> usize { self.pending_leaves.len() }

    fn seal_epoch(&mut self) {
        let leaves     = std::mem::take(&mut self.pending_leaves);
        let prev_root  = self.chain_root;
        let tree       = EpochTree::build(leaves.clone());
        let event_count = leaves.len();

        // Chain: new root = SHA-256(tree_root ‖ prev_root)
        let chained_root = hash_pair(&tree.root, &prev_root);
        self.chain_root  = chained_root;

        let epoch_index = self.sealed.len() as u64;
        eprintln!(
            "[merkle] sealed epoch {} ({} events) root={}",
            epoch_index,
            event_count,
            &self.chain_root.iter().map(|b| format!("{:02x}", b)).collect::<String>()[..16]
        );

        self.sealed.push(SealedEpoch {
            index:       epoch_index,
            root:        chained_root,
            prev_root,
            event_count,
            tree,
        });
    }
}

impl Default for MerkleAuditChain {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469fa72a67b86643c2d
        let hash = sha256(b"abc");
        let hex:  String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469fa72a67b86643c2d0");
    }

    #[test]
    fn sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        let hex:  String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn single_event_proof_verifies() {
        let mut chain = MerkleAuditChain::new();
        // Push enough events to seal one epoch.
        for i in 0..EPOCH_SIZE {
            chain.push(&format!("sess-{}", i), "allow");
        }
        assert_eq!(chain.sealed_epochs().len(), 1);

        // Verify inclusion proof for event 0.
        let proof = chain.proof_for(0).expect("proof for event 0");
        // Re-derive the leaf hash.
        let epoch    = &chain.sealed_epochs()[0];
        let leaf     = epoch.tree.leaves[0];
        assert!(proof.verify(&leaf));
    }

    #[test]
    fn tampered_leaf_fails_verification() {
        let mut chain = MerkleAuditChain::new();
        for i in 0..EPOCH_SIZE {
            chain.push(&format!("s{}", i), "block");
        }
        let proof  = chain.proof_for(5).unwrap();
        let mut bad_leaf = chain.sealed_epochs()[0].tree.leaves[5];
        bad_leaf[0] ^= 0xff; // corrupt one byte
        assert!(!proof.verify(&bad_leaf));
    }

    #[test]
    fn multi_epoch_chain_root_changes() {
        let mut chain = MerkleAuditChain::new();
        for i in 0..(EPOCH_SIZE * 2) {
            chain.push(&format!("s{}", i), "allow");
        }
        assert_eq!(chain.sealed_epochs().len(), 2);
        let root0 = chain.sealed_epochs()[0].root;
        let root1 = chain.sealed_epochs()[1].root;
        assert_ne!(root0, root1);
        // Epoch 1's prev_root must equal epoch 0's chained root.
        assert_eq!(chain.sealed_epochs()[1].prev_root, root0);
    }

    #[test]
    fn flush_seals_partial_epoch() {
        let mut chain = MerkleAuditChain::new();
        chain.push("s1", "allow");
        chain.push("s2", "block");
        assert_eq!(chain.sealed_epochs().len(), 0); // not full
        chain.flush();
        assert_eq!(chain.sealed_epochs().len(), 1);
        assert_eq!(chain.sealed_epochs()[0].event_count, 2);
    }
}
