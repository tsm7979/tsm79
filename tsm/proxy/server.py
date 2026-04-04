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

class AuditLog:
    def __init__(self, path: str = "tsm_audit.jsonl"):
        self.path = path

    def write(self, entry: Dict[str, Any]) -> None:
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps({**entry, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}) + "\n")
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# Shared server state (set on class before serving)
# ─────────────────────────────────────────────────────────────

class _State:
    detector = PIIDetector()
    stats    = Stats()
    audit    = AuditLog()
    skill    = None   # active skill name


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
            self._handle_completion()
        else:
            self._error(404, f"Endpoint not found: {path}")

    # ── Core logic ───────────────────────────────────────────
    def _handle_completion(self) -> None:
        t0 = time.time()

        # Parse body
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
        except Exception:
            self._error(400, "Invalid JSON body")
            return

        model    = body.get("model", "gpt-3.5-turbo")
        messages = body.get("messages", [])
        prompt   = body.get("prompt", "")

        # Combine all user content for scanning
        content = prompt or " ".join(
            m.get("content", "") for m in messages if m.get("role") == "user"
        )

        log_request_start(model, content)

        # PII scan
        result = _State.detector.scan(content)
        log_scan_result(result)

        # Redact if needed
        clean_body = body
        if not result.is_clean:
            log_redaction(result.types)
            clean_messages = [
                {**m, "content": _State.detector.redact(m.get("content", ""))}
                if m.get("role") == "user" else m
                for m in messages
            ]
            clean_body = {**body, "messages": clean_messages}
            if prompt:
                clean_body["prompt"] = _State.detector.redact(prompt)

        # Route
        decision = route(result, model)
        log_route(decision["model"], decision["is_local"], decision["reason"])

        # Update stats
        _State.stats.record(result, decision["is_local"])

        # Build response
        latency = (time.time() - t0) * 1000
        response = self._build_response(body, decision, result, latency)

        log_sent(decision["model"], latency, response.get("_cost", 0))
        response.pop("_cost", None)

        # Audit
        _State.audit.write({
            "model_requested": model,
            "model_used":      decision["model"],
            "pii_detected":    result.types,
            "redacted":        not result.is_clean,
            "routed_local":    decision["is_local"],
            "latency_ms":      round(latency, 1),
        })

        self._json(response)

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

    log_server_start(host, port)

    server = HTTPServer((host, port), TSMHandler)
    _server_instance = server

    if blocking:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n\n  🛑  TSM proxy stopped.\n")
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
