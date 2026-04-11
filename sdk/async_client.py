"""
TSMAsyncClient — async HTTP client for the detector service.

Drop-in async counterpart to sdk/client.py. Use with FastAPI, aiohttp,
asyncio-based applications, or any async framework where blocking the
event loop is not acceptable.

Usage:
    from sdk.async_client import TSMAsyncClient

    client = TSMAsyncClient(org_id="my-org")

    result = await client.detect_text("My SSN is 123-45-6789")
    if result.action == "block":
        raise ValueError("Blocked by TSM policy")

    # As a context manager (connection pool reuse):
    async with TSMAsyncClient() as client:
        result = await client.detect(body)
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from sdk.client import DetectResult


class TSMAsyncClient:
    """
    Async HTTP client for the TSM detector service.

    Uses asyncio streams — zero external dependencies.

    Args:
        url:      detector base URL (default: TSM_DETECTOR_URL env or http://localhost:8001)
        org_id:   workspace / org identifier for multi-tenant deployments
        timeout:  request timeout in seconds
    """

    def __init__(
        self,
        url:     str = "",
        org_id:  str = "default",
        timeout: float = 5.0,
    ) -> None:
        self.url     = (url or os.environ.get("TSM_DETECTOR_URL", "http://localhost:8001")).rstrip("/")
        self.org_id  = org_id
        self.timeout = timeout

    async def detect(self, body: dict[str, Any], user_role: str | None = None) -> DetectResult:
        """Send a chat body to the detector. Returns DetectResult."""
        payload = json.dumps({
            **body,
            "user_role": user_role,
            "metadata":  {"org_id": self.org_id},
        }).encode()

        try:
            data = await self._post("/detect", payload)
        except Exception:
            # Fail open — detector unavailable
            return DetectResult(
                risk_score=0, action="allow", pii_types=[], severity="none",
                redacted_body=body, findings=[], policy_rule=None, latency_ms=0,
            )

        return DetectResult(
            risk_score=data.get("risk_score", 0),
            action=data.get("action", "allow"),
            pii_types=data.get("pii_types", []),
            severity=data.get("severity", "none"),
            redacted_body=data.get("redacted_body", body),
            findings=data.get("findings", []),
            policy_rule=data.get("policy_rule"),
            latency_ms=data.get("latency_ms", 0),
        )

    async def detect_text(
        self,
        text: str,
        model: str = "gpt-3.5-turbo",
        user_role: str | None = None,
    ) -> DetectResult:
        """Convenience: detect a plain text string."""
        return await self.detect(
            body={"model": model, "messages": [{"role": "user", "content": text}]},
            user_role=user_role,
        )

    async def add_rule(self, name: str, condition: dict, action: str, priority: int = 100) -> bool:
        """Add a policy rule. Returns True on success."""
        payload = json.dumps({
            "name": name, "condition": condition,
            "action": action, "priority": priority,
        }).encode()
        try:
            await self._post("/rules", payload)
            return True
        except Exception:
            return False

    async def get_rules(self) -> list[dict]:
        """List all active policy rules."""
        try:
            data = await self._get("/rules")
            return data.get("rules", [])
        except Exception:
            return []

    # ── Internal HTTP helpers using asyncio streams ───────────────────────────

    async def _post(self, path: str, payload: bytes) -> dict[str, Any]:
        import urllib.parse
        parsed = urllib.parse.urlparse(self.url)
        host   = parsed.hostname or "localhost"
        port   = parsed.port or (443 if parsed.scheme == "https" else 8001)
        path_  = parsed.path.rstrip("/") + path

        request = (
            f"POST {path_} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + payload

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self.timeout,
        )
        try:
            writer.write(request)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
        finally:
            writer.close()

        return self._parse_response(response)

    async def _get(self, path: str) -> dict[str, Any]:
        import urllib.parse
        parsed = urllib.parse.urlparse(self.url)
        host   = parsed.hostname or "localhost"
        port   = parsed.port or 8001
        path_  = parsed.path.rstrip("/") + path

        request = (
            f"GET {path_} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self.timeout,
        )
        try:
            writer.write(request)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
        finally:
            writer.close()

        return self._parse_response(response)

    @staticmethod
    def _parse_response(raw: bytes) -> dict[str, Any]:
        """Parse a raw HTTP/1.1 response and return the JSON body."""
        # Split headers from body on blank line
        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            raise ValueError("Invalid HTTP response")
        header_part = raw[:sep].decode("utf-8", errors="replace")
        body = raw[sep + 4:]

        status_line = header_part.split("\r\n", 1)[0]
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            raise ValueError(f"Bad status line: {status_line}")
        status = int(parts[1])
        if status >= 400:
            raise IOError(f"HTTP {status}: {body[:200]!r}")

        return json.loads(body)

    # ── Context manager support ───────────────────────────────────────────────

    async def __aenter__(self) -> "TSMAsyncClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        pass
