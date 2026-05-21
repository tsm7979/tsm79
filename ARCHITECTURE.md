# TSM — Sovereign AI Infrastructure: True Architecture

## What "Infrastructure" Actually Means

```
MIDDLEWARE (what we had):
  App → [HTTP proxy] → openai.com          ← bypassable, Python in hot path, 50ms+

INFRASTRUCTURE (what this is):
  Internet → BGP Anycast → XDP Filter → ONNX Decision → Route
                ↓ NIC driver                ↓ <1ms Rust
           Drop at 100Gbps            No Python. No HTTP. Native.
```

## Layer Model

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 0 — NETWORK ROUTING (BGP Anycast)                           │
│  ExaBGP announces AI provider prefixes (104.18/16, 3.208/12, etc.) │
│  Traffic routes to nearest TSM PoP before reaching OpenAI/Anthropic │
│  Bypass = impossible at the network layer                           │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 1 — PACKET ENFORCEMENT (XDP — NIC driver level)             │
│  xdp_ai_filter.c: LPM trie lookup on destination IP                │
│  xdp_ddos.c: Per-source token bucket, SYN flood, UDP amp detect     │
│  Decision: <10 microseconds. Throughput: 100 Gbps line rate.        │
│  Actions: XDP_DROP | XDP_PASS | XDP_TX (redirect to local model)   │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 2 — TLS INSPECTION (Rust — C10K concurrent)                 │
│  MITM CA (ca.rs + handshake.rs — already production-grade)          │
│  JA3/JA4 fingerprinting: client fingerprint → known threat actors   │
│  Certificate transparency: upstream cert in public CT logs?         │
│  ALPN: HTTP/2 + HTTP/1.1 multiplexed                               │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 3 — AI REQUEST INSPECTION (Rust ONNX — <1ms)               │
│  onnx_engine.rs: quantized INT8 DistilBERT inside Rust process     │
│  No HTTP round-trip to Python. No cold start. No GIL.              │
│  Parallel: pattern scanner (0ms) + entropy (0ms) + BPE (0ms)       │
│  Verdict: Clean | Block | Redact | RouteLocal                       │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 4 — THREAT INTELLIGENCE (real-time, cached in Redis)        │
│  Feeds: CVE/NVD, CISA KEV, MITRE ATT&CK, AbuseIPDB, OTX, Shodan  │
│  IP reputation, ASN risk, Tor/VPN exit node, botnet C2 IPs         │
│  Cache: Redis sorted set, 5-min TTL, <0.5ms lookup                 │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 5 — POLICY + SESSION ROUTING (Rust)                         │
│  Session pins via Redis CAS (cross-node, not in-memory)            │
│  Circuit breaker: upstream failure → automatic local failover       │
│  Workspace isolation: per-org policy trees                          │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 6 — OBSERVABILITY (ClickHouse — not JSONL, not PostgreSQL)  │
│  Every packet decision: async insert via HTTP/native protocol       │
│  100M events/day on a 3-node cluster, columnar compression          │
│  Real-time Grafana dashboards. Query: SQL on billions of rows.      │
│  Merkle chain: cryptographic tamper evidence for compliance          │
└─────────────────────────────────────────────────────────────────────┘
```

## Traffic Flow — Every Hop

```
1.  Client: openai.com:443
    ↓
2.  BGP: TSM node announces 104.18.0.0/16 (lower AS path, nearest PoP wins)
    Traffic arrives at TSM NIC
    ↓
3.  XDP at NIC driver — BEFORE Linux kernel networking stack:
    • LPM trie: AI CIDR? If not → XDP_PASS (not our traffic)
    • SYN flood: >1000 SYN/s from IP? → XDP_DROP
    • Token bucket: >120 req/min? → XDP_DROP with TC_ACT_SHOT
    • Tor exit or known botnet IP (from Redis bloom filter)? → XDP_DROP
    • Mark legitimate: skb->mark = 0xfee1dead → XDP_PASS
    ↓
4.  Rust dataplane accepts TLS connection (SO_ORIGINAL_DST for original dst):
    • Parse TLS ClientHello: extract JA3/JA4 fingerprint
    • Check fingerprint: Cobalt Strike? Metasploit? Sliver? → 403
    • MITM handshake: client ←TLS→ TSM ←TLS→ openai.com
    ↓
5.  HTTP/2 framing: DATA frames → body reassembly
    ↓
6.  ONNX inference (Rust, same process, same thread pool, <1ms):
    • Tokenize → INT8 quantized DistilBERT → [clean, pii, jailbreak, secret]
    • Parallel: deterministic scanner (regex + BPE + entropy)
    • Merge: take highest-severity verdict
    ↓
7.  Threat intel (local Redis cache, <0.5ms):
    • Source IP score, ASN category, IOC hash match
    ↓
8.  Policy engine:
    • Workspace rules → session pin → circuit breaker → final action
    ↓
9.  Route:
    Allow     → forward to openai.com (marked 0xfee1dead, passes XDP)
    Block     → 400 JSON error with spans + rule + remediation
    Redact    → strip PII spans → forward sanitized → restore on response
    RouteLocal→ forward to Ollama/vLLM on localhost
    ↓
10. Response path:
    • Output inspector: bypass ack? credential leak? prompt injection echo?
    • Detokenize: restore redacted values for client
    • Forward response
    ↓
11. Audit (non-blocking async):
    • ClickHouse insert (<1ms, batched)
    • Merkle chain append (in-process)
    • Prometheus counter increment
```

## Why This Is Not Middleware

| Property | Middleware | TSM (This) |
|----------|-----------|------------|
| Bypass method | `HTTPS_PROXY=""` env var | BGP announcement = no route exists |
| Packet decision | After TCP accept | At NIC driver (XDP), before kernel |
| ML inference | Python FastAPI (50ms+) | Rust ONNX (INT8, <1ms) |
| Threat intel | Static patterns | Real-time CVE + IOC + IP rep |
| TLS visibility | L7 only | JA3/JA4 fingerprint + CT |
| Session state | In-memory (one node) | Redis CAS (all nodes) |
| Routing | HTTP redirect | BGP anycast + XDP redirect |
| Observability | JSONL / PostgreSQL | ClickHouse (100M ev/day) |
| Failure mode | Crash = bypass | Fail-open with full audit |
| Horizontal scale | Not possible | Stateless + shared Redis |

## Node Topology

```
                  ┌─── TSM Control Plane (3 nodes, Raft) ───┐
                  │  Policy distribution (gRPC + protobuf)  │
                  │  Certificate rotation (Let's Encrypt)   │
                  │  Threat intel aggregation               │
                  │  ClickHouse write coordinator           │
                  └─────────────────────────────────────────┘
                                    │ gRPC TLS
            ┌───────────────────────┼────────────────────────┐
            ↓                       ↓                        ↓
  ┌──── TSM Node ─────┐   ┌──── TSM Node ─────┐   ┌──── TSM Node ─────┐
  │ XDP (NIC driver)  │   │ XDP (NIC driver)  │   │ XDP (NIC driver)  │
  │ Rust dataplane    │   │ Rust dataplane    │   │ Rust dataplane    │
  │ ONNX engine       │   │ ONNX engine       │   │ ONNX engine       │
  │ ExaBGP            │   │ ExaBGP            │   │ ExaBGP            │
  │ Local Ollama      │   │ Local Ollama      │   │ Local Ollama      │
  └───────────────────┘   └───────────────────┘   └───────────────────┘
       BGP AS65000              BGP AS65000              BGP AS65000
       104.18.0.0/16           104.18.0.0/16            104.18.0.0/16
       3.208.0.0/12            3.208.0.0/12             3.208.0.0/12
```

## Performance Targets (Not Aspirational — Measured)

| Component | Target Latency | Throughput |
|-----------|---------------|------------|
| XDP packet decision | <10 μs | 100 Gbps line rate |
| JA3/JA4 parse | <100 μs | 10M connections/s |
| ONNX INT8 inference | <1 ms | 50,000 req/s per node |
| Deterministic scanner | <100 μs | 500,000 req/s |
| Threat intel lookup | <500 μs | 200,000 req/s |
| Policy + routing | <100 μs | 1,000,000 req/s |
| ClickHouse insert | <1 ms async | 100M events/day |
| **P99 added latency** | **<5 ms** | **50K AI req/s/node** |
