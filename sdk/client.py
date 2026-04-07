"""
TSMClient — low-level HTTP client for the detector service.
Zero external dependencies.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectResult:
    risk_score:    float
    action:        str           # allow | redact | block | route_local
    pii_types:     list[str]
    severity:      str
    redacted_body: dict[str, Any]
    findings:      list[dict]
    policy_rule:   str | None
    latency_ms:    float


class TSMClient:
    """
    Thin HTTP client for the TSM detector service.

    Args:
        url:      detector base URL (default: http://localhost:8001)
        org_id:   workspace / org identifier for multi-tenant deployments
        timeout:  request timeout in seconds
    """

    def __init__(
        self,
        url:     str = "",
        org_id:  str = "default",
        timeout: int = 5,
    ) -> None:
        self.url     = url or os.environ.get("TSM_DETECTOR_URL", "http://localhost:8001")
        self.org_id  = org_id
        self.timeout = timeout

    def detect(self, body: dict[str, Any], user_role: str | None = None) -> DetectResult:
        """Send a chat body to the detector. Returns DetectResult."""
        payload = json.dumps({
            **body,
            "user_role": user_role,
            "metadata":  {"org_id": self.org_id},
        }).encode()

        req = urllib.request.Request(
            f"{self.url}/detect",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read())
        except urllib.error.URLError:
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

    def detect_text(self, text: str, model: str = "gpt-3.5-turbo", user_role: str | None = None) -> DetectResult:
        """Convenience: detect a plain text string."""
        return self.detect(
            body={"model": model, "messages": [{"role": "user", "content": text}]},
            user_role=user_role,
        )

    def add_rule(self, name: str, condition: dict, action: str, priority: int = 100) -> None:
        """Add a policy rule via the detector API."""
        payload = json.dumps({"name": name, "condition": condition, "action": action, "priority": priority}).encode()
        req = urllib.request.Request(f"{self.url}/rules", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout):
            pass

    def get_rules(self) -> list[dict]:
        """List all active policy rules."""
        with urllib.request.urlopen(f"{self.url}/rules", timeout=self.timeout) as r:
            return json.loads(r.read()).get("rules", [])
