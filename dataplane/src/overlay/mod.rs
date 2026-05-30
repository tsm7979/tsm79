//! TSM sovereign overlay — a parallel, ICANN-free name space that rides on top
//! of the existing Internet (Tor/IPFS-class), governed by the TSM data plane.
//!
//! Slice 1 (this module): self-certifying names + a local signed resolver.
//! Slice 2 (pipeline.rs):  a gateway endpoint that resolves `*.tsm` names and
//!                         (because the request flows through the data plane)
//!                         is governed by the existing detect → policy pipeline.
//! Phase 2 (future):       replace the local registry with a libp2p Kademlia DHT
//!                         so the same signed records propagate across a P2P mesh.

pub mod gateway;
pub mod name;
pub mod resolver;

pub use gateway::fetch;
pub use name::{derive_address, NameError, NameRecord, TSM_TLD};
pub use resolver::Resolver;

use std::sync::OnceLock;

static RESOLVER: OnceLock<Resolver> = OnceLock::new();

/// Process-wide overlay resolver (mirrors the `metrics()` singleton pattern).
pub fn resolver() -> &'static Resolver {
    RESOLVER.get_or_init(Resolver::new)
}
