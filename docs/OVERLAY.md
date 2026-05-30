# Sovereign Overlay (`.tsm`)

A self-certifying name layer that rides on top of the existing internet. ICANN-free, opt-in, governed by the same TSM dataplane firewall that governs your AI request path.

This document is the protocol-level reference. For operator quickstart see [DEPLOY.md](DEPLOY.md). For the threat model see [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Goals

1. **Self-certifying** — a name is bound to a public key by a signed record; anyone can verify offline. No DNS, no certificate authority.
2. **Governed by the firewall** — overlay content goes through the same `Detector::scan` path as AI requests. The firewall governs the new network space for free.
3. **Cross-implementation parity** — the Rust dataplane and the Go `overlay-node` produce byte-compatible signing bytes. Records published from one side resolve from the other.
4. **Isolated from public DHTs** — the libp2p protocol prefix is `/tsm`, not the IPFS protocol prefix. There is no accidental cross-pollination with public IPFS content.

## Non-goals

- We are not building a replacement for the public web. We are building a parallel, opt-in space that the same firewall can govern.
- We are not building a privacy network. Use Tor or I2P for that.
- We are not building a generic DHT. The DHT exists to propagate `NameRecord`s; we do not store arbitrary blobs in it.

---

## Names

A `.tsm` name is `<base32(pubkey)>.tsm`. The Tor v3 `.onion` model.

```
ngramotc7f23ek4z7v6m2lkjr5ay83bgkq9j8m2fq6tek4yz3vhc9wd.tsm
└──────────────── base32(Ed25519 pubkey) ────────────────┘.tsm
```

The base32 encoding uses RFC 4648 `A-Z 2-7` with no padding. The result is 52 characters. Lowercase by convention.

`derive_address(pubkey)` is in `dataplane/src/overlay/name.rs`.

---

## `NameRecord`

```rust
struct NameRecord {
    name:       String,    // <base32(pubkey)>.tsm
    pubkey:     [u8; 32],  // Ed25519 public key
    endpoints:  Vec<String>, // http(s):// or self-relative gateway paths
    seq:        u64,       // monotonic per-name, rejects replays
    ttl_secs:   u32,       // resolver caches up to this, then re-resolves
    issued_at:  i64,       // unix seconds, signed
    signature:  [u8; 64],  // Ed25519 over the canonical signing bytes
}
```

### Canonical signing bytes

The bytes the holder of the private key signs over:

```
"tsm-overlay-v1\n"            // domain separation tag
name (utf-8)              "\n"
hex(pubkey)               "\n"
seq.to_string()           "\n"
ttl_secs.to_string()      "\n"
issued_at.to_string()     "\n"
endpoints.join("\n")
```

Implementation: `dataplane/src/overlay/name.rs::canonical_signing_bytes()`.
Cross-implementation parity is verified by `overlay-node/internal/parity_test.go` — given the same field values, the Rust and Go sides produce identical byte sequences.

### Rejected records

The resolver rejects a record if:

- `signature` does not verify under `pubkey`
- `name` does not match `derive_address(pubkey)` (hijack attempt: rebinding the name to a different key)
- `seq` is less than or equal to the most recently observed `seq` for this name (replay attempt)
- `issued_at` is more than `MAX_CLOCK_SKEW` (default 5 minutes) in the future
- The record is older than `ttl_secs` from `issued_at` and we are operating in `strict` cache mode

---

## Resolver

`dataplane/src/overlay/resolver.rs`.

The resolver is a local in-process component the dataplane consults when an overlay name is requested. It has three layers:

1. **Local cache** — `(name, seq, expires_at)` triples held in memory. Lookups never leave the process.
2. **Persistent cache** — `~/.tsm/overlay/cache.sled` (or an operator-chosen path). Survives restarts.
3. **DHT** — falls through to the Go `overlay-node` over a local Unix-domain socket. Cache-miss only.

```
HTTP /_tsm/resolve/<name>
            ↓
   ┌─────────────────────┐
   │   local in-process  │  hit → return
   │       cache         │
   └────────┬────────────┘
            │ miss
            ↓
   ┌─────────────────────┐
   │   sled disk cache   │  hit → verify TTL → return
   └────────┬────────────┘
            │ miss
            ↓
   ┌─────────────────────┐
   │   DHT (libp2p, Go)  │  fetch all candidate records, verify, return newest
   └─────────────────────┘
```

Anti-hijack: if a fresh record has a different `pubkey` than the cached entry for the same `name`, the resolver REJECTS the fresh record (the cached `pubkey` is the source of truth — once you've seen a key for a name, you've seen the key).

Anti-replay: `seq` must monotonically increase per name.

---

## Gateway

`GET /_tsm/<name>`

The dataplane fetches the resolved endpoint, then runs the response body through `Detector::scan` before returning it to the client. This makes the firewall the front door for overlay content the same way it is the front door for AI requests.

Behaviour:

| Verdict from `Detector::scan` | Gateway response |
|---|---|
| `allow` | 200, body forwarded |
| `redact` | 200, body forwarded with PII / secret spans replaced by `[REDACTED:<type>]` |
| `route_local` | 200, body forwarded — but the audit ledger marks it `route_local` |
| `quarantine` | 202, body suppressed, held for human review |
| `block` | 403, body suppressed, reason in `X-TSM-Block-Reason` |

Implementation: `dataplane/src/overlay/gateway.rs`.

---

## DHT — Go libp2p

`overlay-node/` is a libp2p Kademlia DHT under the protocol prefix `/tsm`.

```
go run ./cmd/tsm-overlay-node \
  -listen 0.0.0.0:9001 \
  -bootstrap /ip4/seed.thesovereignmechanica.ai/tcp/9001/p2p/<seed-pid>
```

The node:

- Joins the `/tsm` Kademlia DHT
- Serves `Get(name) → NameRecord` and `Put(NameRecord)` to local processes over a Unix-domain socket
- Periodically re-announces records it has authored (the local publisher's records) every `republish_interval` (default: 30 min)
- Drops records that fail signature verification on PUT (the malicious publisher does not get to poison the DHT)
- Maintains routing tables under `/tsm`, isolated from `/ipfs` and any other DHT

---

## Browser front-door

The MV3 browser extension in `extension/`:

- Registers the `tsm` omnibox keyword. `tsm hub` → `https://gateway.thesovereignmechanica.ai/_tsm/hub.tsm`
- Uses declarativeNetRequest to redirect `*.tsm` navigations to a configurable local or remote gateway
- Has no remote code, no analytics, no telemetry
- Stores the gateway URL in `chrome.storage.local`; the popup lets the operator point at `localhost:8080` for a local dataplane

---

## Publishing

```
tsm overlay keygen                     # generates ~/.tsm/overlay/<name>.key
tsm overlay publish \
  --key ~/.tsm/overlay/<name>.key \
  --endpoint https://app.example.com \
  --ttl 86400
```

The CLI:

1. Reads the Ed25519 private key
2. Computes `derive_address(pubkey)` → the `.tsm` name
3. Fetches the current `seq` from the DHT (if any) and increments
4. Builds the `NameRecord`, computes the canonical signing bytes, signs
5. PUTs the record into the DHT via the local `overlay-node`
6. Verifies resolution from a second peer (sanity check)

---

## Open questions

These are tracked in the [ROADMAP](../ROADMAP.md):

- Mirror replication: signed mirror lists, geographic failover
- Quorum-signed names: multi-key control of a single name
- Post-quantum signatures: hybrid Ed25519 + ML-DSA-65
- Federation: cross-DHT name resolution

---

## References

- Tor v3 `.onion` derivation — <https://spec.torproject.org/rend-spec-v3>
- libp2p Kademlia DHT — <https://github.com/libp2p/specs/tree/master/kad-dht>
- Ed25519 — RFC 8032
- Base32 — RFC 4648
