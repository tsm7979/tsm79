# SDK

How to call TSM79 from your application code. Three forms — choose the one that fits.

---

## Form 1 — drop-in replacement (recommended)

Point your existing OpenAI / Anthropic / Ollama SDK at the dataplane's base URL. **No code changes.**

```bash
export OPENAI_BASE_URL=http://localhost:8080
python your_existing_app.py
```

This works because the dataplane speaks the OpenAI-compatible HTTP contract on `:8080`. Anthropic / Ollama clients have similar one-line config:

```bash
# Anthropic
export ANTHROPIC_BASE_URL=http://localhost:8080

# Ollama-compatible
export OLLAMA_HOST=http://localhost:8080
```

All your application code stays the same. Detection, redaction, routing, and audit happen inline.

---

## Form 2 — Python SDK (`tsm`)

For applications that want fine-grained control of detection + policy without going through HTTP. Useful for batch scans, CI guards, content-pipeline integration.

```bash
pip install tsm
```

### Decorator API

```python
from tsm import protect, TSMBlockedError

@protect
def generate_report(user_prompt: str) -> str:
    # `user_prompt` is scanned before this function body runs.
    # If a critical secret is detected, TSMBlockedError is raised.
    # If PII is detected, `user_prompt` is replaced with the redacted version.
    return call_llm(user_prompt)

try:
    report = generate_report("Customer 123-45-6789 wants a refund")
except TSMBlockedError as e:
    log.warning("blocked: %s", e.reason)
```

### Imperative API

```python
from tsm import scan_text

result = scan_text("My SSN is 123-45-6789 and ghp_DEMO_FIXTURE_NOT_A_REAL_TOKEN_ab12cd")

print(result.verdict)        # block | redact | route_local | quarantine | allow
print(result.pii_types)      # ["SSN", "GITHUB_TOKEN"]
print(result.severity)       # critical
print(result.redacted)       # "My SSN is [REDACTED:SSN] and [REDACTED:GITHUB_TOKEN]"
print(result.risk_score)     # 0-100
```

### Context-manager API

```python
from tsm import scan

with scan("Customer profile: alice@example.com 415-555-0132") as r:
    if r.verdict == "block":
        return error("input refused", reason=r.reason)
    upstream_response = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": r.redacted}],
    )
```

### Client (for non-default servers)

```python
from tsm import TSMClient

client = TSMClient(
    base_url="https://tsm.internal.example.com",
    workspace_id="eng-team",
    api_key="wks_…",
)

result = client.detect_text("hello world")
client.add_rule({"id": "my_rule", "priority": 50, ...})
rules = client.get_rules()
```

The client fails OPEN on network errors by default — if the dataplane is unreachable, the prompt is passed through unmodified. Override with `fail_secure=True` for environments where blocking is preferable to passing.

### LangChain integration

```python
from tsm.langchain import TSMCallbackHandler
from langchain.chat_models import ChatOpenAI

llm = ChatOpenAI(callbacks=[TSMCallbackHandler()])
# Every on_chat_model_start / on_llm_start is intercepted and scanned.
```

---

## Form 3 — gRPC (low-overhead, multi-language)

For high-throughput workloads, talk to the detector directly via gRPC. The contract is in `proto/detector.proto`:

```protobuf
service Detector {
  rpc Scan (ScanRequest) returns (ScanResponse);
  rpc StreamScan (stream ScanRequest) returns (stream ScanResponse);
}

message ScanRequest {
  string text = 1;
  string workspace_id = 2;
  string request_id = 3;
}

message ScanResponse {
  string verdict = 1;
  repeated string pii_types = 2;
  string severity = 3;
  uint32 risk_score = 4;
  string redacted_text = 5;
}
```

Generate clients for your language:

```bash
# Python
python -m grpc_tools.protoc -I proto --python_out=. --grpc_python_out=. proto/detector.proto

# Go
protoc --go_out=. --go-grpc_out=. proto/detector.proto

# Java
protoc --java_out=. --grpc-java_out=. proto/detector.proto
```

Then call:

```python
import grpc, detector_pb2, detector_pb2_grpc

channel = grpc.secure_channel("detector.internal:50051", grpc.ssl_channel_credentials())
stub = detector_pb2_grpc.DetectorStub(channel)
resp = stub.Scan(detector_pb2.ScanRequest(text="..."))
```

gRPC bypasses the dataplane HTTP layer. Use it for batch detection or when you want detection without forwarding. For inflight LLM calls, use Form 1.

---

## CLI

For one-off scans, scripts, CI guards:

```bash
# Scan a string
tsm scan "My SSN is 123-45-6789"

# Scan a file
tsm scan --file path/to/prompt.txt

# Scan stdin
cat prompt.txt | tsm scan -

# JSON output (for CI pipelines)
tsm scan --json "..."

# Apply a policy and exit non-zero on block
tsm scan --policy ci.yaml --exit-on block "..."
```

### CI usage

```yaml
# .github/workflows/prompt-guard.yml
- name: TSM scan changed prompt fixtures
  run: |
    git diff --name-only origin/main HEAD | grep -E '\.prompt$' | while read f; do
      tsm scan --file "$f" --policy ci/strict.yaml --exit-on block,quarantine
    done
```

---

## Error model

Errors map predictably across all SDK forms:

| Condition | HTTP | Python SDK | gRPC |
|---|---|---|---|
| `allow` | upstream's | normal return | `verdict=allow` |
| `redact` | upstream's | normal return, `result.redacted` populated | `verdict=redact`, `redacted_text` populated |
| `route_local` | upstream's | normal return | `verdict=route_local` |
| `quarantine` | 202 | `TSMQuarantinedError` | `verdict=quarantine` |
| `block` | 400 | `TSMBlockedError` | `verdict=block` |
| dataplane unreachable | network error | depends on `fail_secure` flag | `UNAVAILABLE` |
| rate-limited | 429 | `TSMRateLimitedError` | `RESOURCE_EXHAUSTED` |
| auth failure | 401 / 403 | `TSMAuthError` | `UNAUTHENTICATED` / `PERMISSION_DENIED` |

---

## Status

| Form | Status | Notes |
|---|---|---|
| HTTP (drop-in) | **stable** | Production-ready, OpenAI-compatible base URL swap |
| Python SDK | **beta** | API surface stable; polish ongoing |
| gRPC | **stable** | Contract frozen; cross-implementation parity tested |
| Node SDK | **planned** | Q3 2026 |
| Go SDK | **planned** | Q3 2026 |
| Ruby SDK | **considered** | Open an RFC if you'd use this |

---

## Examples

See `tsm/examples/` for runnable examples of each form. The enterprise compose stack ships with `tsm demo` which exercises detection → redaction → forwarding end-to-end in 30 seconds.
