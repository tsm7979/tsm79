"""
Webhook alerting — fires on CRITICAL events.

Supports:
  - Slack (auto-detected by webhook URL format)
  - Microsoft Teams (auto-detected)
  - Generic JSON webhook (anything else)

Config:
  TSM_WEBHOOK_URL   — webhook endpoint (Slack/Teams/custom)
  TSM_ALERT_MIN_RISK — minimum risk score to fire (default: 80)

Usage:
  await alert_if_critical(pii_types, risk_score, severity, model, request_id)
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone


_WEBHOOK_URL  = os.environ.get("TSM_WEBHOOK_URL", "")
_MIN_RISK     = float(os.environ.get("TSM_ALERT_MIN_RISK", "80"))


def _is_slack(url: str) -> bool:
    return "hooks.slack.com" in url

def _is_teams(url: str) -> bool:
    return "webhook.office.com" in url or "outlook.office.com" in url


def _slack_payload(pii_types: list[str], risk_score: float, severity: str, model: str, request_id: str) -> dict:
    color = "#e53e3e" if severity == "critical" else "#dd6b20"
    return {
        "attachments": [{
            "color":  color,
            "title":  f":rotating_light: TSM Alert — {severity.upper()} PII Detected",
            "fields": [
                {"title": "PII Types",   "value": ", ".join(pii_types) or "unknown", "short": True},
                {"title": "Risk Score",  "value": str(risk_score),                    "short": True},
                {"title": "Model",       "value": model,                              "short": True},
                {"title": "Request ID",  "value": request_id,                         "short": True},
            ],
            "footer": "TSM AI Firewall",
            "ts":     int(datetime.now(timezone.utc).timestamp()),
        }]
    }


def _teams_payload(pii_types: list[str], risk_score: float, severity: str, model: str, request_id: str) -> dict:
    return {
        "@type":      "MessageCard",
        "@context":   "https://schema.org/extensions",
        "summary":    f"TSM Alert: {severity.upper()} PII",
        "themeColor": "e53e3e",
        "title":      f"TSM Alert — {severity.upper()} Detected",
        "sections": [{
            "facts": [
                {"name": "PII Types",  "value": ", ".join(pii_types) or "unknown"},
                {"name": "Risk Score", "value": str(risk_score)},
                {"name": "Model",      "value": model},
                {"name": "Request ID", "value": request_id},
                {"name": "Time",       "value": datetime.now(timezone.utc).isoformat()},
            ]
        }]
    }


def _generic_payload(pii_types: list[str], risk_score: float, severity: str, model: str, request_id: str) -> dict:
    return {
        "source":     "tsm-firewall",
        "event":      "pii_detected",
        "severity":   severity,
        "risk_score": risk_score,
        "pii_types":  pii_types,
        "model":      model,
        "request_id": request_id,
        "ts":         datetime.now(timezone.utc).isoformat(),
    }


def _send_sync(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception:
        pass   # never let alerting break the detection path


async def alert_if_critical(
    pii_types:  list[str],
    risk_score: float,
    severity:   str,
    model:      str,
    request_id: str,
) -> None:
    """Fire webhook if risk_score >= threshold. Non-blocking — never raises."""
    if not _WEBHOOK_URL:
        return
    if risk_score < _MIN_RISK:
        return

    url = _WEBHOOK_URL
    if _is_slack(url):
        payload = _slack_payload(pii_types, risk_score, severity, model, request_id)
    elif _is_teams(url):
        payload = _teams_payload(pii_types, risk_score, severity, model, request_id)
    else:
        payload = _generic_payload(pii_types, risk_score, severity, model, request_id)

    # Fire in background thread — don't block the response
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_sync, url, payload)
