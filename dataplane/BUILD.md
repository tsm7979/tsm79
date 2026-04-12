# TSMv2 Dataplane — Build Instructions

## Prerequisites (Linux only)

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# For static musl build (optional, used in Dockerfile)
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools

# eBPF compilation (optional)
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)
```

## Build

```bash
# Debug build (fast compile)
cd TSMv1/dataplane
cargo build

# Release build (optimised, LTO, stripped)
cargo build --release

# Run unit tests
cargo test --lib

# Run with defaults (dev mode, no TLS)
./target/debug/tsm-dataplane
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TSM_LISTEN` | `0.0.0.0:8080` | Bind address |
| `TSM_DETECTOR_URL` | `http://127.0.0.1:8001` | Python detector endpoint |
| `TSM_DETECTOR_TIMEOUT_MS` | `5000` | Detector call timeout |
| `TSM_AUDIT_LOG` | `tsm_audit.log` | Audit log file path |
| `TSM_AUDIT_SECRET` | *(required)* | HMAC secret (32+ bytes) |
| `TSM_POOL_MAX_IDLE` | `8` | Idle connections per upstream |
| `TSM_DETECTOR_FAILURE_MODE` | `allow` | On detector error: allow\|block\|degrade |
| `TSM_RATE_LIMIT` | `100` | Requests/min per IP |
| `TSM_LOG_LEVEL` | `info` | info\|debug\|warn |
| `OPENAI_API_KEY` | — | Forwarded to OpenAI upstream |
| `ANTHROPIC_API_KEY` | — | Forwarded to Anthropic upstream |

## eBPF (Linux + root only)

```bash
# Compile BPF programs
cd TSMv1/ebpf
make
make install   # copies to ../ebpf-loader/bpf/

# Build loader
cd TSMv1/ebpf-loader
cargo build --release

# Attach XDP to loopback (test)
sudo ./target/release/tsm-ebpf-loader --iface lo --port 8080
```

## Docker

```bash
cd TSMv1
docker build -f Dockerfile.dataplane -t tsm-dataplane:2.0.0 .
docker compose up -d
```

## Verification

```bash
# Health check
curl http://localhost:8080/health
# → {"status":"ok"}

# Prometheus metrics
curl http://localhost:8080/metrics

# Block SSN (should return 400)
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}'
# → {"error":{"type":"tsm_policy_violation",...}}

# Allow clean request
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"What is the capital of France?"}]}'
# → proxied to OpenAI (requires OPENAI_API_KEY)
```
