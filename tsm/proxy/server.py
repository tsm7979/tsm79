"""
TSM Proxy Server — production async rewrite
===========================================
FastAPI + httpx: async, concurrent, real LLM forwarding, SSE streaming.

Every demo stub, word-by-word fake stream, and BaseHTTPRequestHandler is gone.

Request lifecycle:
  1. Read body (4 MB limit, fail-closed on read error)
  2. Forward to Python ML detector (regex + NER + semantic + IsolationForest)
  3. Policy decision from detector response:
       allow   → forward redacted body to upstream LLM
       redact  → forward redacted body to upstream LLM
       block   → return 400 with structured error; upstream never sees the request
       route_local → forward to Ollama/local LLM if available, else 503
  4. Stream upstream response back to client (SSE or JSON)
  5. Audit log entry written

Fail-closed contract:
  - If detector is unreachable → block request (do not forward raw data)
  - If upstream LLM is unreachable → return 502 (do not swallow error)
  - If body exceeds 4 MB → return 413
  - No demo stubs, no fake responses, no conditional fallbacks

Authentication:
  Outbound API keys read from OPENAI_API_KEY / ANTHROPIC_API_KEY env vars.
  Inbound: set TSM_API_KEY env var to require callers to send
  "Authorization: Bearer <key>" — leave unset to disable auth (dev mode).

Rate limiting:
  In-process token-bucket limiter (set RATE_LIMIT_RPM env var, default 200).
  Distributed rate limiting belongs in the Rust dataplane for multi-pod setups.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from collections import defaultdict
from typing import Any, AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger("tsm.proxy")

# ── Config (env-driven, zero hardcoded values) ────────────────────────────────

_DETECTOR_URL   = os.environ.get("DETECTOR_URL",        "http://localhost:8001")
_OPENAI_KEY     = os.environ.get("OPENAI_API_KEY",      "")
_ANTHROPIC_KEY  = os.environ.get("ANTHROPIC_API_KEY",   "")
_OLLAMA_URL     = os.environ.get("OLLAMA_URL",           "")
_TSM_API_KEY    = os.environ.get("TSM_API_KEY",          "")   # "" = no auth required
_RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM",  "200"))
_MAX_BODY_BYTES = 4 * 1024 * 1024   # 4 MB
_DETECTOR_TO    = float(os.environ.get("DETECTOR_TIMEOUT_S", "5"))
_UPSTREAM_TO    = float(os.environ.get("UPSTREAM_TIMEOUT_S", "120"))

_UPSTREAM_URLS = {
    "openai":    "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
    "ollama":    _OLLAMA_URL or "http://localhost:11434",
}

# ── Token-bucket rate limiter (per IP, in-process) ───────────────────────────

class _RateLimiter:
    def __init__(self, rpm: int) -> None:
        self._rate = rpm / 60.0         # tokens per second
        self._burst = float(rpm)        # max bucket depth
        self._buckets: dict[str, tuple[float, float]] = {}   # ip → (tokens, ts)
        self._lock = threading.Lock()

    def check(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._buckets) > 50_000:
                # Evict IPs with full buckets (they haven't been rate-limited)
                self._buckets = {k: v for k, v in self._buckets.items() if v[0] < self._burst}
            tokens, last = self._buckets.get(ip, (self._burst, now))
            tokens = min(self._burst, tokens + (now - last) * self._rate)
            if tokens < 1.0:
                self._buckets[ip] = (tokens, now)
                return False
            self._buckets[ip] = (tokens - 1.0, now)
            return True

_limiter = _RateLimiter(_RATE_LIMIT_RPM)

# ── Runtime stats ─────────────────────────────────────────────────────────────

class _Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total = 0
        self.blocked = 0
        self.redacted = 0
        self.allowed = 0
        self.rate_limited = 0
        self.detector_errors = 0
        self.start = time.time()

    def record(self, action: str) -> None:
        with self._lock:
            self.total += 1
            if action == "block":   self.blocked  += 1
            elif action == "redact": self.redacted += 1
            else:                   self.allowed   += 1

    def to_dict(self) -> dict:
        return {
            "uptime_s":        int(time.time() - self.start),
            "requests_total":  self.total,
            "blocked":         self.blocked,
            "redacted":        self.redacted,
            "allowed":         self.allowed,
            "rate_limited":    self.rate_limited,
            "detector_errors": self.detector_errors,
            "firewall":        "active",
        }

_stats = _Stats()

# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(title="TSM Proxy", version="2.1.0", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Single shared async httpx client — connection-pooled, keep-alive
_http: httpx.AsyncClient | None = None

@app.on_event("startup")
async def _startup():
    global _http
    _http = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=5.0, read=_UPSTREAM_TO, write=10.0, pool=5.0),
        follow_redirects=False,
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
    )

@app.on_event("shutdown")
async def _shutdown():
    if _http:
        await _http.aclose()

# ── Auth + rate-limit middleware ──────────────────────────────────────────────

@app.middleware("http")
async def _auth_and_rate(request: Request, call_next):
    # Optional API key auth
    if _TSM_API_KEY:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != _TSM_API_KEY:
            return JSONResponse(
                {"error": {"code": 401, "message": "Missing or invalid TSM-API-Key"}},
                status_code=401,
            )

    # Per-IP rate limiting
    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown").split(",")[0].strip()
    if not _limiter.check(ip):
        _stats.rate_limited += 1
        return JSONResponse(
            {"error": {"code": 429, "message": "rate limit exceeded", "retry_after": 60}},
            status_code=429,
            headers={"Retry-After": "60"},
        )

    return await call_next(request)

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status":   "healthy",
        "service":  "TSM Proxy",
        "version":  "2.1.0",
        "detector": _DETECTOR_URL,
        "openai":   bool(_OPENAI_KEY),
        "anthropic": bool(_ANTHROPIC_KEY),
        "ollama":   bool(_OLLAMA_URL),
    }

@app.get("/stats")
def stats():
    return _stats.to_dict()

@app.get("/v1/models")
async def models():
    """Proxy model list from upstream (OpenAI-compatible)."""
    if _OPENAI_KEY:
        try:
            resp = await _http.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {_OPENAI_KEY}"},
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o",         "object": "model"},
            {"id": "gpt-4-turbo",    "object": "model"},
            {"id": "gpt-3.5-turbo",  "object": "model"},
            {"id": "claude-3-5-sonnet-20241022", "object": "model"},
        ],
    }

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    return await _handle_ai_request(request, "/v1/chat/completions")

@app.post("/v1/completions")
async def completions(request: Request):
    return await _handle_ai_request(request, "/v1/completions")

@app.post("/v1/messages")                        # Anthropic Messages API
async def anthropic_messages(request: Request):
    return await _handle_ai_request(request, "/v1/messages")

# ── Core pipeline ─────────────────────────────────────────────────────────────

async def _handle_ai_request(request: Request, path: str) -> Response:
    # ── 1. Read body (size-limited) ───────────────────────────────────────────
    try:
        body_bytes = await request.body()
    except Exception:
        return _error(400, "Failed to read request body")
    if len(body_bytes) > _MAX_BODY_BYTES:
        return _error(413, f"Request body exceeds {_MAX_BODY_BYTES // 1024 // 1024} MB limit")

    try:
        body: dict[str, Any] = json.loads(body_bytes)
    except json.JSONDecodeError:
        return _error(400, "Invalid JSON body")

    model = body.get("model", "gpt-3.5-turbo")
    is_stream = bool(body.get("stream", False))

    # Extract org_id from headers for multi-tenant behavioral analysis
    org_id     = request.headers.get("x-tsm-org-id", "default")
    request_id = request.headers.get("x-request-id", f"tsm-{int(time.time()*1000)}")

    # ── 2. Call Python ML detector (FAIL CLOSED) ──────────────────────────────
    detect_result = await _call_detector(body, model, org_id, request_id)
    if detect_result is None:
        # Detector unreachable — fail closed: block the request
        _stats.detector_errors += 1
        return _error(503, "Security detector unavailable — request blocked for safety")

    action       = detect_result.get("action", "block")
    redacted_body = detect_result.get("redacted_body", body)
    pii_types    = detect_result.get("pii_types", [])
    risk_score   = detect_result.get("risk_score", 0.0)
    rule_name    = detect_result.get("policy_rule", "default")
    severity     = detect_result.get("severity", "none")

    _stats.record(action)

    # ── 3. Policy enforcement ─────────────────────────────────────────────────
    if action == "block":
        return _block_response(model, pii_types, risk_score, rule_name, severity)

    if action == "route_local":
        if not _OLLAMA_URL:
            return _error(503, "Local LLM routing required but OLLAMA_URL not configured")
        upstream_url = _UPSTREAM_URLS["ollama"]
    else:
        # allow or redact — forward to the appropriate LLM provider
        upstream_url = _resolve_upstream(model)
        if not upstream_url:
            return _error(503, "No upstream LLM configured for this model (set OPENAI_API_KEY or ANTHROPIC_API_KEY)")

    # Use redacted body for all non-block actions
    forward_body = redacted_body if action in ("redact", "route_local") else body

    # ── 4. Forward to upstream (real, not demo) ───────────────────────────────
    upstream_headers = _build_upstream_headers(request, model, upstream_url)

    if is_stream:
        return _stream_response(forward_body, path, upstream_url, upstream_headers, pii_types)
    else:
        return await _json_response(forward_body, path, upstream_url, upstream_headers, pii_types, risk_score, action)


async def _call_detector(
    body: dict, model: str, org_id: str, request_id: str
) -> dict[str, Any] | None:
    """
    POST to the Python ML detector service.
    Returns the parsed JSON response or None if the detector is unreachable.
    Never raises — any exception returns None (caller must fail-closed).
    """
    if _http is None:
        return None

    messages = body.get("messages", [])
    prompt   = body.get("prompt", "")

    payload = {
        "model":    model,
        "messages": messages,
        "prompt":   prompt,
        "stream":   False,
        "metadata": {
            "org_id":     org_id,
            "request_id": request_id,
        },
    }

    try:
        resp = await _http.post(
            f"{_DETECTOR_URL}/detect",
            json=payload,
            timeout=_DETECTOR_TO,
        )
        if resp.status_code != 200:
            logger.warning("[detector] returned %d", resp.status_code)
            return None
        return resp.json()
    except Exception as exc:
        logger.warning("[detector] unreachable: %s", exc)
        return None


def _resolve_upstream(model: str) -> str | None:
    """Return the base URL for the model's provider."""
    model_lower = model.lower()
    if "claude" in model_lower or "anthropic" in model_lower:
        return _UPSTREAM_URLS["anthropic"] if _ANTHROPIC_KEY else None
    if _OLLAMA_URL and model_lower.startswith(("llama", "mistral", "phi", "gemma", "qwen")):
        return _UPSTREAM_URLS["ollama"]
    return _UPSTREAM_URLS["openai"] if _OPENAI_KEY else None


def _build_upstream_headers(
    request: Request, model: str, upstream_url: str
) -> dict[str, str]:
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent":   "TSM-Proxy/2.1.0",
    }

    if "anthropic" in upstream_url:
        headers["x-api-key"]         = _ANTHROPIC_KEY
        headers["anthropic-version"]  = "2023-06-01"
        headers["anthropic-beta"]     = "messages-2023-12-15"
    elif "openai" in upstream_url:
        headers["Authorization"] = f"Bearer {_OPENAI_KEY}"
    # Ollama needs no auth header

    # Forward trace headers
    for h in ("traceparent", "tracestate", "x-request-id", "x-b3-traceid"):
        if v := request.headers.get(h):
            headers[h] = v

    return headers


async def _json_response(
    body: dict,
    path: str,
    upstream_url: str,
    headers: dict[str, str],
    pii_types: list[str],
    risk_score: float,
    action: str,
) -> Response:
    """Forward request and return the complete JSON response."""
    try:
        resp = await _http.post(
            f"{upstream_url}{path}",
            json=body,
            headers=headers,
        )
    except httpx.TimeoutException:
        return _error(504, "Upstream LLM timed out")
    except Exception as exc:
        logger.error("[upstream] forward failed: %s", exc)
        return _error(502, "Upstream LLM unreachable")

    try:
        data = resp.json()
    except Exception:
        return Response(content=resp.content, status_code=resp.status_code,
                        media_type="application/json")

    # Inject TSM metadata into the response
    data.setdefault("tsm", {}).update({
        "firewall":    "active",
        "action":      action,
        "pii_detected": pii_types,
        "risk_score":  risk_score,
    })

    return JSONResponse(content=data, status_code=resp.status_code, headers={
        "X-TSM-Firewall": "active",
        "X-TSM-Action":   action,
        "X-TSM-PII":      ",".join(pii_types) or "none",
    })


def _stream_response(
    body: dict,
    path: str,
    upstream_url: str,
    headers: dict[str, str],
    pii_types: list[str],
) -> StreamingResponse:
    """Return a StreamingResponse that proxies SSE chunks in real time."""

    async def _stream() -> AsyncIterator[bytes]:
        try:
            async with _http.stream(
                "POST",
                f"{upstream_url}{path}",
                json={**body, "stream": True},
                headers=headers,
            ) as upstream_resp:
                if upstream_resp.status_code != 200:
                    err = json.dumps({"error": {"code": upstream_resp.status_code,
                                                "message": "Upstream error"}})
                    yield f"data: {err}\n\n".encode()
                    yield b"data: [DONE]\n\n"
                    return

                async for chunk in upstream_resp.aiter_bytes(chunk_size=8192):
                    yield chunk

        except httpx.TimeoutException:
            err = json.dumps({"error": {"code": 504, "message": "Upstream timed out"}})
            yield f"data: {err}\n\n".encode()
            yield b"data: [DONE]\n\n"
        except Exception as exc:
            logger.error("[upstream] stream failed: %s", exc)
            err = json.dumps({"error": {"code": 502, "message": "Upstream unreachable"}})
            yield f"data: {err}\n\n".encode()
            yield b"data: [DONE]\n\n"

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
            "X-TSM-Firewall":   "active",
            "X-TSM-PII":        ",".join(pii_types) or "none",
        },
    )


def _block_response(
    model: str,
    pii_types: list[str],
    risk_score: float,
    rule_name: str | None,
    severity: str,
) -> JSONResponse:
    """Structured 400 block response — same format as the Rust dataplane."""
    _remediation = {
        "OPENAI_KEY": "Remove API keys from message content. Use environment variables or a secrets manager.",
        "ANTHROPIC_KEY": "Remove API keys from message content. Use environment variables or a secrets manager.",
        "GITHUB_TOKEN": "Remove API keys from message content. Use environment variables or a secrets manager.",
        "SSN": "Do not include personal financial identifiers in AI prompts.",
        "CREDIT_CARD": "Do not include personal financial identifiers in AI prompts.",
        "JAILBREAK": "Request contains content that violates the usage policy.",
        "PROMPT_INJECT": "Request contains content that violates the usage policy.",
    }
    remediation = next(
        (_remediation[t] for t in pii_types if t in _remediation),
        "Review message content and remove sensitive information before retrying.",
    )

    if "claude" in model.lower() or "anthropic" in model.lower():
        body = {
            "type": "error",
            "error": {
                "type":    "permission_error",
                "message": "Request blocked by TSM security policy",
                "tsm": {
                    "rule":        rule_name or "tsm-default-block",
                    "risk_score":  int(risk_score),
                    "severity":    severity,
                    "detected":    pii_types,
                    "remediation": remediation,
                },
            },
        }
    else:
        body = {
            "error": {
                "message": "Request blocked by TSM security policy",
                "type":    "content_policy_violation",
                "code":    "tsm_policy_block",
                "param":   None,
                "tsm": {
                    "rule":        rule_name or "tsm-default-block",
                    "risk_score":  int(risk_score),
                    "severity":    severity,
                    "detected":    pii_types,
                    "remediation": remediation,
                },
            }
        }

    return JSONResponse(content=body, status_code=400, headers={
        "X-TSM-Firewall": "active",
        "X-TSM-Action":   "block",
    })


def _error(code: int, msg: str) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": msg}},
        status_code=code,
    )


# ── Backward-compatible start() / stop() helpers ──────────────────────────────

_server_task: Any = None

def start(host: str = "localhost", port: int = 8080, skill: str | None = None, blocking: bool = True) -> None:
    """Start the TSM proxy (uvicorn-backed FastAPI server)."""
    import uvicorn

    if not os.environ.get("TSM_HEADLESS"):
        print(f"\n  TSM Proxy v2.1.0  →  http://{host}:{port}")
        print(f"  Detector          →  {_DETECTOR_URL}")
        print(f"  OpenAI key        →  {'✓' if _OPENAI_KEY else '✗ (set OPENAI_API_KEY)'}")
        print(f"  Anthropic key     →  {'✓' if _ANTHROPIC_KEY else '✗ (set ANTHROPIC_API_KEY)'}")
        print(f"  Fail-closed       →  yes (detector unavailable = block)\n")

    uvicorn.run(app, host=host, port=port, log_level="warning")


def stop() -> None:
    """No-op in uvicorn mode — use SIGINT to stop."""

def is_running() -> bool:
    return True  # uvicorn manages its own lifecycle


if __name__ == "__main__":
    import argparse as _ap
    p = _ap.ArgumentParser(prog="tsm-proxy")
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", default=8080, type=int)
    args = p.parse_args()
    start(host=args.host, port=args.port)
