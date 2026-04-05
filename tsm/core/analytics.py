"""
TSM Analytics
=============
Reads the trust ledger and computes real usage insights.

No external dependencies — pure stdlib.

The enterprise analytics layer in internal/analytics/ builds on top of
this with time-series storage, dashboards, and multi-tenant aggregation.
This module handles the single-user, single-machine case.
"""
from __future__ import annotations

import json
import pathlib
import time
from collections import defaultdict
from typing import Any, Dict, List

_LEDGER_PATH = pathlib.Path.home() / ".tsm" / "ledger.jsonl"


def load_intercepts(path: pathlib.Path = _LEDGER_PATH) -> List[Dict[str, Any]]:
    """Load all 'intercept' entries from the ledger."""
    if not path.exists():
        return []
    entries: List[Dict] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if e.get("type") == "intercept":
                        entries.append(e)
                except json.JSONDecodeError:
                    pass
    except OSError:
        pass
    return entries


def compute(path: pathlib.Path = _LEDGER_PATH) -> Dict[str, Any]:
    """
    Aggregate all intercept entries into a stats dict.

    Returns:
        total          — total interceptions
        clean          — no PII found
        redacted       — PII found and redacted
        local_routes   — routed to local model (critical PII)
        cloud_routes   — forwarded to cloud
        local_ratio    — fraction routed locally
        cost_saved     — USD saved by local routing
        pii_types      — {type: count}, sorted by frequency
        severity_dist  — {severity: count}
        top_models     — {model: count}
        avg_latency_ms — average proxy overhead
        hourly_24h     — {hours_ago: count} for last 24 hours
        peak_hour      — which hour_ago had most traffic
    """
    entries = load_intercepts(path)

    if not entries:
        return {
            "total": 0,
            "clean": 0,
            "redacted": 0,
            "local_routes": 0,
            "cloud_routes": 0,
            "local_ratio": 0.0,
            "cost_saved": 0.0,
            "pii_types": {},
            "severity_dist": {},
            "top_models": {},
            "avg_latency_ms": 0.0,
            "hourly_24h": {},
            "peak_hour": None,
        }

    total = len(entries)
    pii_counts: Dict[str, int] = defaultdict(int)
    severity_dist: Dict[str, int] = defaultdict(int)
    model_counts: Dict[str, int] = defaultdict(int)
    cost_saved = 0.0
    local_count = 0
    redacted_count = 0
    latency_sum = 0.0
    hourly: Dict[int, int] = defaultdict(int)
    now = time.time()
    cutoff_24h = now - 86400

    for e in entries:
        for t in e.get("pii_types", []):
            pii_counts[t] += 1

        sev = e.get("severity", "none")
        severity_dist[sev] += 1

        model = e.get("model", "unknown")
        model_counts[model] += 1

        cost_saved += e.get("cost_saved", 0.0)

        if e.get("routed_local"):
            local_count += 1

        if e.get("redacted"):
            redacted_count += 1

        latency_sum += e.get("latency_ms", 0.0)

        # Parse timestamp for hourly bucketing
        ts = e.get("ts", "")
        if ts:
            try:
                import datetime
                dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                # Use timestamp() on a naive UTC datetime
                epoch = (dt - datetime.datetime(1970, 1, 1)).total_seconds()
                if epoch >= cutoff_24h:
                    hours_ago = int((now - epoch) // 3600)
                    hourly[min(hours_ago, 23)] += 1
            except Exception:
                pass

    peak_hour = min(hourly, key=lambda h: (hourly[h], -h)) if hourly else None

    return {
        "total": total,
        "clean": total - redacted_count,
        "redacted": redacted_count,
        "local_routes": local_count,
        "cloud_routes": total - local_count,
        "local_ratio": round(local_count / total, 3) if total else 0.0,
        "cost_saved": round(cost_saved, 6),
        "pii_types": dict(sorted(pii_counts.items(), key=lambda x: -x[1])),
        "severity_dist": dict(severity_dist),
        "top_models": dict(sorted(model_counts.items(), key=lambda x: -x[1])),
        "avg_latency_ms": round(latency_sum / total, 1) if total else 0.0,
        "hourly_24h": dict(sorted(hourly.items())),
        "peak_hour": peak_hour,
    }


def spark_bar(value: int, max_value: int, width: int = 20) -> str:
    """Return an ASCII bar scaled to max_value."""
    if max_value == 0:
        return " " * width
    filled = round(value / max_value * width)
    return "#" * filled + "." * (width - filled)
