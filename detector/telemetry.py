"""
OpenTelemetry OTLP export for the TSM Detector service.

Why OTel:
  Enterprise SIEMs (Splunk, Datadog, Elastic, Grafana) ingest OTLP traces.
  Every /detect call becomes a span with risk_score, action, pii_types, and
  latency as attributes — giving security teams a searchable audit trail in
  their existing observability stack without TSM-specific integrations.

Architecture:
  - One TracerProvider per process, configured once at startup.
  - Spans are batched and exported via gRPC OTLP (port 4317) by default.
  - HTTP OTLP (port 4318) is supported via TSM_OTEL_EXPORTER=http.
  - If opentelemetry-sdk is not installed, all calls are no-ops (graceful degradation).
  - Service name defaults to "tsm-detector"; override with TSM_OTEL_SERVICE_NAME.

Env vars:
  OTEL_EXPORTER_OTLP_ENDPOINT  — collector address (default: http://localhost:4317)
  TSM_OTEL_EXPORTER            — "grpc" (default) | "http" | "none"
  TSM_OTEL_SERVICE_NAME        — service.name resource attribute
  TSM_OTEL_ENABLED             — "true" | "false" (default: "true" if endpoint set)

Usage:
  from detector.telemetry import init_telemetry, trace_detect_call, record_exception

  # Call once at app startup (main.py on_event("startup")):
  init_telemetry()

  # Wrap each /detect call:
  with trace_detect_call(org_id, model, action, pii_types, risk_score, latency_ms):
      ...  # the span is auto-closed on exit
"""

from __future__ import annotations

import contextlib
import logging
import os
from typing import Generator

logger = logging.getLogger("tsm.telemetry")

# ── OTel availability probe ───────────────────────────────────────────────────

_OTEL_OK = False
_tracer  = None

try:
    import importlib.util as _ilu
    _OTEL_OK = (
        _ilu.find_spec("opentelemetry.sdk") is not None
        and _ilu.find_spec("opentelemetry.exporter.otlp") is not None
    )
except Exception:
    _OTEL_OK = False

# ── Configuration ─────────────────────────────────────────────────────────────

_ENDPOINT     = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
_EXPORTER     = os.environ.get("TSM_OTEL_EXPORTER", "grpc").lower()
_SERVICE_NAME = os.environ.get("TSM_OTEL_SERVICE_NAME", "tsm-detector")
_ENABLED      = os.environ.get("TSM_OTEL_ENABLED", "").lower()

# Auto-enable when an explicit endpoint is configured; disable if set to "false"
_SHOULD_INIT  = _ENABLED != "false" and (
    _ENABLED == "true"
    or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
)


# ── Init ──────────────────────────────────────────────────────────────────────

def init_telemetry() -> bool:
    """
    Initialise the TracerProvider and register the OTLP exporter.

    Returns True if OTel was successfully configured, False if the SDK is
    absent or initialisation failed (caller can log a one-time warning).

    Safe to call multiple times — subsequent calls after the first are no-ops.
    """
    global _tracer, _OTEL_OK

    if _tracer is not None:
        return True  # already initialised

    if not _OTEL_OK or not _SHOULD_INIT:
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({
            "service.name":    _SERVICE_NAME,
            "service.version": "2.0.0",
            "deployment.environment": os.environ.get("ENVIRONMENT", "production"),
        })

        provider = TracerProvider(resource=resource)

        # ── Build the exporter ────────────────────────────────────────────────
        exporter = _build_exporter()
        if exporter is None:
            return False

        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        _tracer = trace.get_tracer(__name__, schema_url="https://opentelemetry.io/schemas/1.22.0")
        logger.info("[telemetry] OTel OTLP export active → %s (%s)", _ENDPOINT, _EXPORTER)
        return True

    except Exception as exc:
        logger.warning("[telemetry] OTel init failed: %s", exc)
        return False


def _build_exporter():
    """Build the appropriate OTLP exporter based on TSM_OTEL_EXPORTER."""
    try:
        if _EXPORTER == "http":
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            # HTTP endpoint conventionally uses /v1/traces suffix
            endpoint = _ENDPOINT.rstrip("/")
            if not endpoint.endswith("/v1/traces"):
                endpoint = endpoint + "/v1/traces"
            return OTLPSpanExporter(endpoint=endpoint)
        else:
            # Default: gRPC
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            return OTLPSpanExporter(endpoint=_ENDPOINT, insecure=not _ENDPOINT.startswith("https"))
    except Exception as exc:
        logger.warning("[telemetry] exporter build failed: %s", exc)
        return None


# ── Span helpers ──────────────────────────────────────────────────────────────

@contextlib.contextmanager
def trace_detect_call(
    org_id:     str,
    model:      str,
    action:     str,
    pii_types:  list[str],
    risk_score: float,
    latency_ms: float,
) -> Generator[None, None, None]:
    """
    Context manager that wraps a /detect call in an OTel span.

    Usage:
        with trace_detect_call(org_id, model, action, pii_types, risk, lat):
            ...  # span auto-closed on exit

    If OTel is not configured, the context manager is a transparent no-op.
    """
    if _tracer is None:
        yield
        return

    try:
        from opentelemetry import trace
        from opentelemetry.trace import StatusCode

        with _tracer.start_as_current_span("tsm.detect") as span:
            span.set_attribute("tsm.org_id",      org_id)
            span.set_attribute("tsm.model",       model)
            span.set_attribute("tsm.action",      action)
            span.set_attribute("tsm.pii_types",   ",".join(pii_types))
            span.set_attribute("tsm.risk_score",  round(risk_score, 2))
            span.set_attribute("tsm.latency_ms",  round(latency_ms, 2))
            span.set_attribute("tsm.pii_count",   len(pii_types))

            if action == "block":
                span.set_status(StatusCode.ERROR, "request blocked by policy")
            else:
                span.set_status(StatusCode.OK)

            yield
    except Exception:
        yield   # never let OTel errors surface to callers


@contextlib.contextmanager
def trace_upstream_call(
    upstream: str,
    model:    str,
    path:     str,
) -> Generator[None, None, None]:
    """Span for the outbound LLM upstream call (proxy-side)."""
    if _tracer is None:
        yield
        return

    try:
        from opentelemetry import trace
        from opentelemetry.trace import StatusCode

        with _tracer.start_as_current_span("tsm.upstream") as span:
            span.set_attribute("tsm.upstream", upstream)
            span.set_attribute("tsm.model",    model)
            span.set_attribute("http.target",  path)
            yield
            span.set_status(StatusCode.OK)
    except Exception:
        yield


def record_exception(exc: Exception) -> None:
    """Record an exception on the current active span (no-op if OTel absent)."""
    if _tracer is None:
        return
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        if span.is_recording():
            span.record_exception(exc)
    except Exception:
        pass


def is_enabled() -> bool:
    """Return True if OTel tracing is active."""
    return _tracer is not None
