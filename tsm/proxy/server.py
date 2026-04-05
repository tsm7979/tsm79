"""
TSM Proxy Server
================
OpenAI-compatible HTTP proxy that intercepts every AI call,
detects PII, redacts it, routes intelligently, and logs visibly.

Endpoints:
    POST /v1/chat/completions   — OpenAI-compatible chat
    POST /v1/completions        — OpenAI-compatible completion
    GET  /health                — health check
    GET  /stats                 — live statistics
    GET  /v1/models             — pass-through models list
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tsm.detectors.pii import PIIDetector, ScanResult, Severity
from tsm.detectors.semantic import SemanticDetector
from tsm.proxy.logger import (
    log_request_start, log_scan_result, log_redaction,
    log_route, log_sent, log_blocked, log_server_start,
)

logger = logging.getLogger("tsm.proxy")

# ─────────────────────────────────────────────────────────────
# Router
# ─────────────────────────────────────────────────────────────

def route(result: ScanResult, requested_model: str) -> Dict[str, Any]:
    """Return routing decision based on scan result."""
    if result.has_critical:
        return {
            "model":    "local",
            "is_local": True,
            "reason":   f"critical PII detected ({', '.join(result.types)})",
            "blocked":  False,
        }
    if result.has_high:
        return {
            "model":    requested_model,
            "is_local": False,
            "reason":   f"high-risk data redacted ({', '.join(result.types)})",
            "blocked":  False,
        }
    if not result.is_clean:
        return {
            "model":    requested_model,
            "is_local": False,
            "reason":   f"PII redacted ({', '.join(result.types)})",
            "blocked":  False,
        }
    return {
        "model":    requested_model,
        "is_local": False,
        "reason":   "clean",
        "blocked":  False,
    }


# ─────────────────────────────────────────────────────────────
# Stats tracker
# ─────────────────────────────────────────────────────────────

@dataclass
class Stats:
    requests_total:   int = 0
    requests_clean:   int = 0
    requests_redacted: int = 0
    requests_blocked: int = 0
    pii_types_seen:   Dict[str, int] = field(default_factory=dict)
    total_cost_saved: float = 0.0   # cost avoided by routing locally
    start_time:       float = field(default_factory=time.time)

    def record(self, result: ScanResult, is_local: bool) -> None:
        self.requests_total += 1
        if result.is_clean:
            self.requests_clean += 1
        else:
            self.requests_redacted += 1
        for t in result.types:
            self.pii_types_seen[t] = self.pii_types_seen.get(t, 0) + 1
        if is_local:
            self.total_cost_saved += 0.002  # rough estimate per request

    def to_dict(self) -> Dict[str, Any]:
        uptime = int(time.time() - self.start_time)
        return {
            "uptime_seconds":    uptime,
            "requests_total":    self.requests_total,
            "requests_clean":    self.requests_clean,
            "requests_redacted": self.requests_redacted,
            "requests_blocked":  self.requests_blocked,
            "pii_types_detected": self.pii_types_seen,
            "cost_saved_usd":    round(self.total_cost_saved, 4),
            "firewall":          "active",
        }


# ─────────────────────────────────────────────────────────────
# Audit logger
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
# Shared server state (set on class before serving)
# ─────────────────────────────────────────────────────────────

def _make_ledger():
    try:
        from tsm.core.ledger import TrustLedger
        return TrustLedger()
    except Exception:
        return None

def _make_policy():
    try:
        from tsm.core.policy import PolicyEngine
        return PolicyEngine()
    except Exception:
        return None


class _State:
    detector  = PIIDetector()
    semantic  = SemanticDetector()
    stats     = Stats()
    ledger    = _make_ledger()    # crypto-chained audit trail
    policy    = _make_policy()    # configurable policy engine
    skill     = None              # active skill name


# ─────────────────────────────────────────────────────────────
# HTTP Request Handler
# ─────────────────────────────────────────────────────────────

class TSMHandler(BaseHTTPRequestHandler):
    """Handles every HTTP request to the proxy."""

    log_message = lambda *_: None  # silence default HTTP logs

    # ── GET ──────────────────────────────────────────────────
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._json({"status": "healthy", "service": "TSM Proxy", "version": "2.0.0"})
        elif path == "/stats":
            self._json(_State.stats.to_dict())
        elif path == "/v1/models":
            self._json({"object": "list", "data": [
                {"id": "gpt-4",          "object": "model"},
                {"id": "gpt-3.5-turbo",  "object": "model"},
                {"id": "local",          "object": "model"},
            ]})
        else:
            self._error(404, f"Not found: {path}")

    # ── POST ─────────────────────────────────────────────────
    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path in ("/v1/chat/completions", "/v1/completions"):
            # Read body first to check if stream=true
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw    = self.rfile.read(length)
                body   = json.loads(raw)
            except Exception:
                self._error(400, "Invalid JSON body")
                return
            if body.get("stream"):
                self._handle_stream(body)
            else:
                self._handle_completion(body)
        else:
            self._error(404, f"Endpoint not found: {path}")

    # ── Core logic ───────────────────────────────────────────
    def _handle_completion(self, body: Dict) -> None:
        t0 = time.time()

        model    = body.get("model", "gpt-3.5-turbo")
        messages = body.get("messages", [])
        prompt   = body.get("prompt", "")

        # Combine all user content for scanning
        content = prompt or " ".join(
            m.get("content", "") for m in messages if m.get("role") == "user"
        )

        log_request_start(model, content)

        # ── Layer 1: Regex PII scan ───────────────────────────
        result = _State.detector.scan(content)
        log_scan_result(result)

        # ── Layer 2: Semantic analysis (jailbreak, entropy, contextual PII)
        sem = _State.semantic.scan(content)
        # Merge semantic findings into the all_types list for routing/logging
        all_pii_types = list(result.types) + sem.types
        # Escalate severity if semantic found something worse
        effective_severity = result.worst_severity
        if sem.worst_severity is not None:
            order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            sem_idx = order.index(sem.worst_severity) if sem.worst_severity in order else 99
            cur_idx = order.index(effective_severity) if effective_severity in order else 99
            if sem_idx < cur_idx:
                effective_severity = sem.worst_severity

        # Jailbreak = always block
        if any(f.type == "JAILBREAK_ATTEMPT" for f in sem.findings):
            latency = (time.time() - t0) * 1000
            self._error(400, "[TSM] Request blocked: prompt injection detected")
            log_blocked("jailbreak_attempt", latency)
            _State.stats.requests_blocked += 1
            return

        # ── Layer 3: Redact ───────────────────────────────────
        clean_body = body
        if not result.is_clean or not sem.is_clean:
            log_redaction(all_pii_types)
            clean_messages = []
            for m in messages:
                if m.get("role") == "user":
                    txt = _State.detector.redact(m.get("content", ""))
                    txt = _State.semantic.redact(txt, sem)
                    clean_messages.append({**m, "content": txt})
                else:
                    clean_messages.append(m)
            clean_body = {**body, "messages": clean_messages}
            if prompt:
                txt = _State.detector.redact(prompt)
                clean_body["prompt"] = _State.semantic.redact(txt, sem)

        # ── Layer 4: Route ────────────────────────────────────
        decision = route(result, model)
        # Override to local if semantic escalated severity to CRITICAL
        if effective_severity == Severity.CRITICAL and not decision["is_local"]:
            decision = {
                "model": "local", "is_local": True, "blocked": False,
                "reason": f"semantic escalation ({', '.join(sem.types)})",
            }
        log_route(decision["model"], decision["is_local"], decision["reason"])

        # Update stats
        _State.stats.record(result, decision["is_local"])

        # Build response
        latency = (time.time() - t0) * 1000
        response = self._build_response(body, decision, result, latency)

        log_sent(decision["model"], latency, response.get("_cost", 0))
        response.pop("_cost", None)

        # Audit — write to crypto-chained trust ledger
        if _State.ledger is not None:
            tokens = len(json.dumps(body)) // 4
            _State.ledger.log_intercept(
                model=decision["model"],
                pii_types=all_pii_types,
                severity=effective_severity.value if effective_severity else "none",
                routed_local=decision["is_local"],
                redacted=not result.is_clean or not sem.is_clean,
                latency_ms=latency,
                prompt_tokens=tokens,
            )

        self._json(response)

    def _handle_stream(self, body: Dict) -> None:
        """
        Streaming (SSE) path — stream=true requests.

        The proxy:
          1. Scans + redacts the prompt (same detection pipeline as non-stream)
          2. Sends the TSM decision as the first SSE chunk
          3. Emits the content word-by-word as subsequent SSE chunks
          4. Closes with [DONE]

        In production, step 3 would forward to the real API with stream=true
        and pipe the SSE response back. This implementation generates a demo
        response so the tool works with zero API keys while demonstrating
        the full streaming interface.
        """
        import socket

        t0    = time.time()
        model = body.get("model", "gpt-3.5-turbo")
        messages = body.get("messages", [])
        prompt   = body.get("prompt", "")

        content = prompt or " ".join(
            m.get("content", "") for m in messages if m.get("role") == "user"
        )

        # ── Detection pipeline (same as non-stream) ───────────
        result = _State.detector.scan(content)
        sem    = _State.semantic.scan(content)
        all_pii_types = list(result.types) + sem.types

        if any(f.type == "JAILBREAK_ATTEMPT" for f in sem.findings):
            self._error(400, "[TSM] Request blocked: prompt injection detected")
            return

        # Redact
        clean_body = body
        if not result.is_clean or not sem.is_clean:
            clean_msgs = []
            for m in messages:
                if m.get("role") == "user":
                    txt = _State.detector.redact(m.get("content", ""))
                    txt = _State.semantic.redact(txt, sem)
                    clean_msgs.append({**m, "content": txt})
                else:
                    clean_msgs.append(m)
            clean_body = {**body, "messages": clean_msgs}

        decision = route(result, model)

        # ── Ledger ────────────────────────────────────────────
        latency = (time.time() - t0) * 1000
        if _State.ledger is not None:
            tokens = len(json.dumps(body)) // 4
            effective_sev = result.worst_severity
            _State.ledger.log_intercept(
                model=decision["model"],
                pii_types=all_pii_types,
                severity=effective_sev.value if effective_sev else "none",
                routed_local=decision["is_local"],
                redacted=not result.is_clean or not sem.is_clean,
                latency_ms=latency,
                prompt_tokens=tokens,
            )
        _State.stats.record(result, decision["is_local"])

        # ── Build streaming reply ─────────────────────────────
        cid = f"chatcmpl-tsm-stream-{int(time.time()*1000)}"
        if decision["is_local"]:
            reply = (
                f"[TSM] Request kept local. "
                f"Detected: {', '.join(all_pii_types) or 'none'}. "
                f"Cloud never saw this data."
            )
        else:
            reply = (
                f"[TSM Demo] Forwarded to {decision['model']}. "
                f"PII redacted: {', '.join(all_pii_types) or 'none'}."
            )

        # ── Send SSE response ─────────────────────────────────
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-TSM-Firewall", "active")
        self.send_header("X-TSM-PII", ",".join(all_pii_types) or "none")
        self.end_headers()

        words = reply.split()
        for i, word in enumerate(words):
            chunk = {
                "id": cid, "object": "chat.completion.chunk",
                "created": int(time.time()), "model": decision["model"],
                "choices": [{"index": 0, "delta": {"content": word + (" " if i < len(words)-1 else "")}, "finish_reason": None}],
            }
            self._sse(json.dumps(chunk))
            time.sleep(0.015)  # simulate token-by-token pacing

        # Final chunk with finish_reason
        final = {
            "id": cid, "object": "chat.completion.chunk",
            "created": int(time.time()), "model": decision["model"],
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
        self._sse(json.dumps(final))
        self._sse("[DONE]")

    def _build_response(
        self,
        body: Dict,
        decision: Dict,
        result: ScanResult,
        latency_ms: float,
    ) -> Dict[str, Any]:
        """Build an OpenAI-compatible response."""
        model_used = decision["model"]
        is_local   = decision["is_local"]

        # Rough cost
        content_len = len(json.dumps(body))
        tokens_est  = content_len // 4
        costs = {"gpt-4": 0.045, "gpt-4-turbo": 0.015, "gpt-3.5-turbo": 0.001}
        cost = 0 if is_local else (tokens_est / 1000) * costs.get(model_used, 0.01)

        if is_local:
            text = (
                "🔒 [TSM] Request processed locally — sensitive data was not sent to any cloud service.\n\n"
                f"Detected: {', '.join(result.types)}\n"
                "In production, this would be forwarded to your local LLM (Ollama, llama.cpp, etc.)"
            )
        else:
            text = (
                f"[TSM Demo] Request forwarded to {model_used}.\n"
                f"PII redacted: {', '.join(result.types) if result.types else 'none'}\n"
                "In production, this calls the real API."
            )

        return {
            "id":      f"chatcmpl-tsm-{int(time.time()*1000)}",
            "object":  "chat.completion",
            "created": int(time.time()),
            "model":   model_used,
            "choices": [{
                "index":         0,
                "message":       {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens":     tokens_est,
                "completion_tokens": len(text) // 4,
                "total_tokens":      tokens_est + len(text) // 4,
            },
            "tsm": {
                "firewall":        "active",
                "pii_detected":    result.types,
                "severity":        result.worst_severity.value if result.worst_severity else "none",
                "redacted":        not result.is_clean,
                "routed_local":    is_local,
                "routing_reason":  decision["reason"],
                "latency_ms":      round(latency_ms, 1),
            },
            "_cost": cost,
        }

    # ── Helpers ──────────────────────────────────────────────
    def _sse(self, data: str) -> None:
        """Write one SSE event."""
        try:
            line = f"data: {data}\n\n".encode("utf-8")
            self.wfile.write(line)
            self.wfile.flush()
        except Exception:
            pass

    def _json(self, data: Dict) -> None:
        payload = json.dumps(data, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-TSM-Firewall", "active")
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, code: int, msg: str) -> None:
        payload = json.dumps({"error": {"code": code, "message": msg}}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

_server_instance: Optional[HTTPServer] = None
_server_thread:   Optional[threading.Thread] = None


def start(host: str = "localhost", port: int = 8080, skill: str | None = None, blocking: bool = True) -> None:
    """Start the TSM proxy server."""
    global _server_instance, _server_thread

    if skill:
        _State.skill = skill

    # Suppress banner in headless/daemon mode (stdout may not be a real terminal)
    if not os.environ.get("TSM_HEADLESS"):
        log_server_start(host, port)

    server = HTTPServer((host, port), TSMHandler)
    _server_instance = server

    if blocking:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n\n  TSM proxy stopped.\n")
            server.shutdown()
    else:
        _server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        _server_thread.start()


def stop() -> None:
    """Stop the proxy server."""
    global _server_instance
    if _server_instance:
        _server_instance.shutdown()
        _server_instance = None


def is_running() -> bool:
    return _server_instance is not None


if __name__ == "__main__":
    import argparse as _ap
    p = _ap.ArgumentParser(prog="tsm-proxy")
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", default=8080, type=int)
    p.add_argument("--skill", default=None)
    a = p.parse_args()
    start(host=a.host, port=a.port, skill=a.skill, blocking=True)
