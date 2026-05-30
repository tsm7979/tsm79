"""
TSM Detector — gRPC service implementation.

Implements DetectService and BehavioralService from proto/detect.proto.
The Rust dataplane calls Detect() via tonic; Python handles the ML layers:
  - Isolation Forest anomaly scoring     (anomaly.py)
  - Sentence-transformer semantic scan   (semantic.py)
  - spaCy NER                            (classifier.py)
  - LLM-assisted classification          (classifier.py)
  - CVSS risk scoring                    (risk_scorer.py)
  - Behavioral analysis                  (behavioral.py)
  - Correlation engine                   (correlation.py)

Fast-path detection (regex + entropy + structural) runs in Rust. This service
only receives requests that Rust marked as "Ambiguous" — roughly 10-20% of
traffic. Do NOT move fast-path logic here.

Starting the server:
  python -m detector.grpc_server         # port from GRPC_PORT env (default 50051)

Generating stubs from proto:
  pip install grpcio-tools
  python -m grpc_tools.protoc \\
    -I proto \\
    --python_out=detector/gen \\
    --grpc_python_out=detector/gen \\
    proto/detect.proto
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

# ── gRPC imports ──────────────────────────────────────────────────────────────
# The generated stubs live in detector/gen/.  If they don't exist yet (e.g.,
# during development without grpcio-tools), we fall back to the HTTP FastAPI
# server and print a clear warning.

_GRPC_OK = False
try:
    import grpc
    import grpc.aio
    _GRPC_OK = True
except ImportError:
    pass

_STUBS_OK = False
try:
    sys.path.insert(0, str(Path(__file__).parent / "gen"))
    import detect_pb2       as pb2       # noqa: F401
    import detect_pb2_grpc  as pb2_grpc  # noqa: F401
    _STUBS_OK = True
except ImportError:
    pass

# ── Application imports ───────────────────────────────────────────────────────

from detector.classifier  import Classifier
from detector.risk_scorer import score_findings, severity_from_level
from detector.sanitizer   import Sanitizer
from detector.correlation import correlate
from detector.behavioral  import get_analyzer
from detector.anomaly     import get_anomaly_detector
from detector.semantic    import get_semantic_detector
from detector.alerting    import alert_if_critical

_classifier  = Classifier()
_sanitizer   = Sanitizer()


# ── gRPC servicer ─────────────────────────────────────────────────────────────

class DetectServicer:
    """Implements DetectService (from detect.proto)."""

    async def Detect(self, request, context):
        """
        Full ML detection pipeline for one request.

        The Rust dataplane has already run regex + entropy + structural.
        This service adds: NER, semantic embeddings, Isolation Forest,
        LLM-assisted classification, behavioral analysis, correlation.
        """
        t0 = time.time()

        text = request.prompt or " ".join(
            m.content for m in request.messages if m.role == "user"
        )
        org_id = request.org_id or "default"

        # ── NER (spaCy) ───────────────────────────────────────────────────────
        ner_findings = _classifier.ner_scan(text)
        scan         = _classifier.scan(text)  # regex pass (cheap, for span info)
        for f in ner_findings:
            scan.merge_structural([f])

        # ── Semantic embeddings ───────────────────────────────────────────────
        sem_detector = get_semantic_detector()
        if sem_detector.available:
            sem_findings = await asyncio.get_event_loop().run_in_executor(
                None, sem_detector.scan, text
            )
            scan.merge_structural(sem_findings)

        # ── LLM-assisted classification (ambiguous only) ───────────────────────
        if scan.needs_llm_assist:
            llm_findings = await _classifier.llm_classify(text, scan.raw_findings)
            scan.merge_llm(llm_findings)

        # ── CVSS risk scoring ─────────────────────────────────────────────────
        if scan.pii_types:
            cvss_score, cvss_level, _ = score_findings(scan.pii_types)
            final_risk    = max(scan.risk_score, cvss_score)
            final_severity = severity_from_level(cvss_level)
        else:
            final_risk    = scan.risk_score
            final_severity = scan.severity

        # ── Correlation ───────────────────────────────────────────────────────
        _, final_risk, _ = correlate(org_id, scan.pii_types, final_risk)

        # ── Behavioral analysis ───────────────────────────────────────────────
        behavioral = get_analyzer()
        anomaly    = behavioral.observe_and_analyse(org_id, scan.pii_types, len(text))
        if anomaly.is_anomalous:
            final_risk = min(100.0, final_risk + anomaly.composite_score * 20.0)

        # ── Isolation Forest ──────────────────────────────────────────────────
        iforest = get_anomaly_detector()
        vel_events   = behavioral._backend.query(f"behavioral:{org_id}", 60.0)
        exfil_events = behavioral._backend.query(f"behavioral:{org_id}", 600.0)
        iforest_score = iforest.observe(org_id, vel_events, exfil_events)
        if iforest_score > 0.7:
            final_risk = min(100.0, final_risk + iforest_score * 15.0)

        # ── Policy action ─────────────────────────────────────────────────────
        action_str = _action_from_risk(final_risk, scan.pii_types)

        # ── Redaction ─────────────────────────────────────────────────────────
        redacted_text = text
        if action_str in ("redact", "route_local"):
            san = _sanitizer.sanitize(text)
            redacted_text = san.sanitized_text

        # ── Spans ─────────────────────────────────────────────────────────────
        if _STUBS_OK:
            spans = [
                pb2.Span(
                    start=f.get("start", 0), end=f.get("end", 0),
                    pii_type=f.get("type", ""),
                    severity=f.get("severity", ""),
                    layer=f.get("layer", "regex"),
                )
                for f in scan.raw_findings
            ]
            action_enum = {
                "allow":       pb2.DetectAction.ALLOW,
                "redact":      pb2.DetectAction.REDACT,
                "block":       pb2.DetectAction.BLOCK,
                "route_local": pb2.DetectAction.ROUTE_LOCAL,
            }.get(action_str, pb2.DetectAction.ALLOW)

            response = pb2.DetectResponse(
                risk_score         = final_risk,
                action             = action_enum,
                pii_types          = scan.pii_types,
                severity           = final_severity,
                redacted_body      = redacted_text,
                spans              = spans,
                policy_rule        = "",
                latency_ms         = (time.time() - t0) * 1000,
                anomaly_score      = iforest_score,
                behavioral_signals = anomaly.signals,
            )
        else:
            response = _DictResponse(
                risk_score=final_risk, action=action_str,
                pii_types=scan.pii_types, severity=final_severity,
                redacted_body=redacted_text, latency_ms=(time.time() - t0) * 1000,
                anomaly_score=iforest_score, behavioral_signals=anomaly.signals,
            )

        # ── Critical alerting (non-blocking) ──────────────────────────────────
        if action_str in ("block", "route_local") or final_risk >= 80:
            asyncio.create_task(alert_if_critical(
                pii_types=scan.pii_types, risk_score=final_risk,
                severity=final_severity, model=request.model,
                request_id=request.request_id,
            ))

        return response

    async def DetectStream(self, request, context):
        """
        Server-streaming variant: yields a DetectResponse per detection layer
        as it completes, allowing the Rust dataplane to begin forwarding the
        sanitized body before all ML layers finish.
        """
        # Layer 1: NER (fast, synchronous)
        ner   = _classifier.ner_scan(request.prompt or "")
        scan  = _classifier.scan(request.prompt or "")
        for f in ner:
            scan.merge_structural([f])

        if _STUBS_OK:
            yield pb2.DetectResponse(
                risk_score = scan.risk_score,
                pii_types  = scan.pii_types,
                severity   = scan.severity,
            )

        # Layer 2: Semantic (may be slow)
        sem = get_semantic_detector()
        if sem.available:
            sem_findings = await asyncio.get_event_loop().run_in_executor(
                None, sem.scan, request.prompt or ""
            )
            scan.merge_structural(sem_findings)

        # Yield final enriched response
        full = await self.Detect(request, context)
        yield full


class BehavioralServicer:
    """Implements BehavioralService (from detect.proto)."""

    async def GetStats(self, request, context):
        org_id    = request.org_id
        behavioral = get_analyzer()
        stats     = behavioral.org_stats(org_id)
        iforest   = get_anomaly_detector()
        info      = iforest.model_info(org_id)
        if _STUBS_OK:
            return pb2.BehavioralStatsResponse(
                org_id        = org_id,
                events_60s    = stats.get("events_60s",   0),
                events_10min  = stats.get("events_10min", 0),
                anomaly_score = 0.0,
                model_status  = info.get("status",  "unseen"),
                model_samples = info.get("samples", 0),
            )
        return _DictResponse(**stats, **info)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _action_from_risk(risk: float, pii_types: list[str]) -> str:
    """Map risk score + PII types to a policy action string."""
    critical_types = {"SSN", "CREDIT_CARD", "OPENAI_KEY", "ANTHROPIC_KEY",
                      "AWS_KEY", "PRIVATE_KEY", "GITHUB_TOKEN", "STRIPE_SECRET"}
    if risk >= 80 or any(t in critical_types for t in pii_types):
        return "block"
    if risk >= 40:
        return "redact"
    if risk > 0:
        return "redact"
    return "allow"


class _DictResponse:
    """Fallback when protobuf stubs haven't been generated yet."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


# ── Server startup ────────────────────────────────────────────────────────────

async def _serve() -> None:
    if not _GRPC_OK:
        print(
            "[TSM] grpcio not installed. Run: pip install grpcio grpcio-tools\n"
            "[TSM] Falling back to HTTP server (detector/main.py).",
            file=sys.stderr,
        )
        return

    if not _STUBS_OK:
        print(
            "[TSM] gRPC stubs not generated. Run:\n"
            "  python -m grpc_tools.protoc -I proto "
            "--python_out=detector/gen --grpc_python_out=detector/gen proto/detect.proto",
            file=sys.stderr,
        )
        return

    port = int(os.environ.get("GRPC_PORT", 50051))
    server = grpc.aio.server()
    pb2_grpc.add_DetectServiceServicer_to_server(DetectServicer(), server)
    pb2_grpc.add_BehavioralServiceServicer_to_server(BehavioralServicer(), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    await server.start()
    print(f"[TSM] gRPC DetectService listening on :{port}", file=sys.stderr)
    await server.wait_for_termination()


if __name__ == "__main__":
    asyncio.run(_serve())
