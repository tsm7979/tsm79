"""
TSM Detector Service — Python FastAPI
======================================
Dedicated detection microservice. The TypeScript proxy calls this for every
request. Separation of concerns: proxy handles HTTP, detector handles ML.

Why Python here?
  - Best ML ecosystem (scikit-learn, spaCy, transformers)
  - LLM-assisted classification via existing adapter layer
  - Regex + entropy + structural parsing in a maintained library ecosystem
  - Future: swap in a GPU-accelerated model without touching the proxy

Endpoints:
  POST /detect    — scan a chat body, return risk + action + redacted body
  GET  /health    — liveness check
  GET  /rules     — current policy rules
  POST /rules     — add/update a rule
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure tsm package is importable (detector lives one level below repo root)
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root))

from detector.classifier  import Classifier
from detector.policy_engine import PolicyEngine, PolicyRule
from detector.alerting    import alert_if_critical
from detector.workspace   import registry as workspace_registry
from detector.risk_scorer import score_findings, severity_from_level
from detector.sanitizer   import Sanitizer
from detector.correlation import correlate, correlation_stats
from detector.behavioral  import get_analyzer
from detector.anomaly     import get_anomaly_detector
from detector.semantic    import get_semantic_detector
from detector.presidio_layer import scan as presidio_scan, is_available as presidio_available
from detector.tokenizer   import get_tokenizer
from detector.telemetry   import init_telemetry, trace_detect_call, record_exception, is_enabled as otel_enabled
from detector.speculative_security import SecurityCascade, CascadeVerdict
from detector.output_inspector import OutputInspector, OutputInspectResult

# ── Config ────────────────────────────────────────────────────────────────────

_DETECTOR_KEY  = os.environ.get("TSM_DETECTOR_KEY", "")   # empty = no auth
_AUDIT_PATH    = Path(os.environ.get("AUDIT_LOG_PATH", "/tmp/tsm_audit.jsonl"))

# ── Audit log ────────────────────────────────────────────────────────────────

_audit_lock = threading.Lock()

def _write_audit(record: dict) -> None:
    """Append one JSON line to the audit log (thread-safe, fail-silent)."""
    try:
        with _audit_lock:
            with _AUDIT_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception:
        pass  # never block the request path for audit I/O errors

# ── Prometheus metrics ────────────────────────────────────────────────────────

class _Metrics:
    """Minimal thread-safe counters — no prometheus_client dependency required."""

    def __init__(self) -> None:
        self._lock       = threading.Lock()
        self.requests    = 0
        self.allowed     = 0
        self.blocked     = 0
        self.redacted    = 0
        self.route_local = 0
        self.errors      = 0
        self._latencies: list[float] = []   # last 10 000 latency samples (ms)

    def record(self, action: str, latency_ms: float) -> None:
        with self._lock:
            self.requests += 1
            if action == "allow":
                self.allowed += 1
            elif action == "block":
                self.blocked += 1
            elif action == "redact":
                self.redacted += 1
            elif action == "route_local":
                self.route_local += 1
            self._latencies.append(latency_ms)
            if len(self._latencies) > 10_000:
                self._latencies = self._latencies[-10_000:]

    def record_error(self) -> None:
        with self._lock:
            self.requests += 1
            self.errors   += 1

    def prometheus_text(self) -> str:
        with self._lock:
            lat  = sorted(self._latencies) if self._latencies else [0.0]
            p50  = lat[int(len(lat) * 0.50)]
            p95  = lat[int(len(lat) * 0.95)]
            p99  = lat[int(len(lat) * 0.99)]
            lines = [
                "# HELP tsm_requests_total Total detect requests",
                "# TYPE tsm_requests_total counter",
                f"tsm_requests_total {self.requests}",
                "# HELP tsm_allowed_total Requests allowed through",
                "# TYPE tsm_allowed_total counter",
                f"tsm_allowed_total {self.allowed}",
                "# HELP tsm_blocked_total Requests blocked by policy",
                "# TYPE tsm_blocked_total counter",
                f"tsm_blocked_total {self.blocked}",
                "# HELP tsm_redacted_total Requests with PII redacted",
                "# TYPE tsm_redacted_total counter",
                f"tsm_redacted_total {self.redacted}",
                "# HELP tsm_route_local_total Requests routed to local model",
                "# TYPE tsm_route_local_total counter",
                f"tsm_route_local_total {self.route_local}",
                "# HELP tsm_errors_total Internal errors during detection",
                "# TYPE tsm_errors_total counter",
                f"tsm_errors_total {self.errors}",
                "# HELP tsm_detect_latency_ms_p50 Latency p50 (ms)",
                "# TYPE tsm_detect_latency_ms_p50 gauge",
                f"tsm_detect_latency_ms_p50 {p50:.2f}",
                "# HELP tsm_detect_latency_ms_p95 Latency p95 (ms)",
                "# TYPE tsm_detect_latency_ms_p95 gauge",
                f"tsm_detect_latency_ms_p95 {p95:.2f}",
                "# HELP tsm_detect_latency_ms_p99 Latency p99 (ms)",
                "# TYPE tsm_detect_latency_ms_p99 gauge",
                f"tsm_detect_latency_ms_p99 {p99:.2f}",
            ]
        return "\n".join(lines) + "\n"

_metrics = _Metrics()

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="TSM Detector",
    version="2.0.0",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth middleware ───────────────────────────────────────────────────────────

_OPEN_PATHS = {"/health", "/metrics", "/docs", "/openapi.json"}

@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    """
    When TSM_DETECTOR_KEY is set, all endpoints except /health and /metrics
    require Authorization: Bearer <key> or X-TSM-Key: <key>.
    Returns 401 on missing/wrong key — never exposes the reason in the body.
    """
    if _DETECTOR_KEY and request.url.path not in _OPEN_PATHS:
        auth   = request.headers.get("Authorization", "")
        tsm_hdr = request.headers.get("X-TSM-Key", "")
        token  = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        if token != _DETECTOR_KEY and tsm_hdr != _DETECTOR_KEY:
            return Response(
                content='{"error":{"code":"unauthorized","message":"Invalid or missing API key"}}',
                status_code=401,
                media_type="application/json",
            )
    return await call_next(request)

classifier       = Classifier()
policy_engine    = PolicyEngine()
sanitizer        = Sanitizer()
security_cascade = SecurityCascade()
output_inspector = OutputInspector()


@app.on_event("startup")
async def _startup() -> None:
    """Initialise optional subsystems (OTel, warm-up ML models, etc.)."""
    if not init_telemetry():
        pass  # OTel absent or disabled — silent, not an error

# ── Schema ────────────────────────────────────────────────────────────────────

class DetectRequest(BaseModel):
    model: str = "gpt-3.5-turbo"
    messages: list[dict[str, Any]] = []
    prompt: str = ""
    stream: bool = False
    user_role: str | None = None
    metadata: dict[str, Any] = {}

class Finding(BaseModel):
    type: str
    severity: str
    context: str
    redacted: bool

class DetectResponse(BaseModel):
    risk_score: float
    action: str           # allow | redact | block | route_local
    pii_types: list[str]
    severity: str
    redacted_body: dict[str, Any]
    findings: list[Finding]
    policy_rule: str | None
    latency_ms: float
    # Tokenization fields (populated when action == "redact"):
    # vault_id lets the proxy call POST /detokenize with the LLM response.
    vault_id: str | None = None
    presidio_available: bool = False

class ScanResponseRequest(BaseModel):
    """Scan an AI model's response text for PII leakage."""
    response_text: str
    model: str = "gpt-3.5-turbo"
    request_id: str | None = None
    metadata: dict[str, Any] = {}

class ScanResponseResult(BaseModel):
    """Result of scanning an AI response for PII leakage."""
    pii_found: bool
    pii_types: list[str]
    risk_score: float
    severity: str
    redacted_text: str
    findings: list[Finding]
    latency_ms: float

class RuleRequest(BaseModel):
    name: str
    condition: dict[str, Any]
    action: str
    priority: int = 100

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    sem = get_semantic_detector()
    return {
        "status":              "healthy",
        "service":             "TSM Detector",
        "version":             "2.0.0",
        "llm_assist":          bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")),
        "semantic":            sem.available,
        "isolation_forest":    True,
        "correlation":         correlation_stats(),
        "grpc_port":           int(os.environ.get("GRPC_PORT", 50051)),
        "auth_enabled":        bool(_DETECTOR_KEY),
        "presidio":            presidio_available(),
        "otel_tracing":        otel_enabled(),
        "cascade_tier1_ready": security_cascade.tier1_ready(),
        "cascade_tier2_ready": security_cascade.tier2_ready(),
        "output_inspector":    True,
    }

@app.get("/metrics")
def metrics():
    """Prometheus-compatible text metrics for Grafana scraping."""
    return Response(content=_metrics.prometheus_text(), media_type="text/plain; version=0.0.4")

@app.get("/behavioral/stats/{org_id}")
def behavioral_stats(org_id: str):
    """Return live velocity, exfiltration stats + Isolation Forest model info."""
    stats  = get_analyzer().org_stats(org_id)
    imodel = get_anomaly_detector().model_info(org_id)
    return {**stats, "isolation_forest": imodel}

@app.post("/detect", response_model=DetectResponse)
async def detect(req: DetectRequest):  # noqa: C901
    try:
        return await _detect_impl(req)
    except Exception as exc:
        _metrics.record_error()
        raise HTTPException(status_code=500, detail=str(exc)) from exc


async def _detect_impl(req: DetectRequest) -> DetectResponse:
    t0 = time.time()

    # Extract full text for analysis
    text = req.prompt or " ".join(
        m.get("content", "") for m in req.messages if m.get("role") == "user"
    )

    org_id      = req.metadata.get("org_id", "default")
    session_id  = req.metadata.get("session_id", "unknown")
    request_id  = req.metadata.get("request_id", "unknown")

    # ── Stage 0: Speculative security cascade ────────────────────────────────
    # 3-tier cascade: Tier 0 (deterministic BPE+regex, 0ms) →
    #                  Tier 1 (DistilBERT CPU, ~50ms) →
    #                  Tier 2 (7B full model, ~500ms, only when uncertain).
    # 90%+ of requests resolve at Tier 0.  Tier 1/2 are cold-started lazily.
    cascade_verdict: CascadeVerdict = await asyncio.get_event_loop().run_in_executor(
        None,
        security_cascade.classify,
        text, org_id, req.model, session_id,
    )
    if cascade_verdict.action == "block":
        # Short-circuit: deterministic or model-confirmed block.
        latency = (time.time() - t0) * 1000
        _metrics.record("block", latency)
        _write_audit({
            "ts": time.time(), "request_id": request_id, "org_id": org_id,
            "model": req.model, "action": "block",
            "pii_types": cascade_verdict.pii_types,
            "risk_score": round(cascade_verdict.risk_score, 2),
            "severity": "critical", "rule": "cascade-tier0-block",
            "latency_ms": round(latency, 2), "stage": cascade_verdict.tier,
        })
        return DetectResponse(
            risk_score=cascade_verdict.risk_score,
            action="block",
            pii_types=cascade_verdict.pii_types,
            severity="critical",
            redacted_body=dict(req.model_dump()),
            findings=[],
            policy_rule=f"cascade-{cascade_verdict.tier}",
            latency_ms=round(latency, 2),
            presidio_available=presidio_available(),
        )

    # ── Stage 1: Fast regex + entropy scan ─────────────────────────────────
    scan = classifier.scan(text)

    # ── Stage 2: LLM-assisted classification for ambiguous findings ─────────
    if scan.needs_llm_assist:
        llm_findings = await classifier.llm_classify(text, scan.findings)
        scan.merge_llm(llm_findings)

    # ── Stage 3: Structural parsing (API keys, JWTs, etc.) ───────────────
    structural = classifier.structural_scan(text)
    scan.merge_structural(structural)

    # ── Stage 4: spaCy NER — prose PII (names, addresses, orgs) ─────────
    ner_findings = classifier.ner_scan(text)
    if ner_findings:
        scan.merge_structural(ner_findings)

    # ── Stage 4b: Semantic embedding scan — context-aware PII ────────────────
    # Catches medical/financial/adversarial context that regex cannot see.
    # Runs in executor so it doesn't block the async event loop.
    sem = get_semantic_detector()
    if sem.available:
        sem_findings = await asyncio.get_event_loop().run_in_executor(
            None, sem.scan, text
        )
        if sem_findings:
            scan.merge_structural(sem_findings)

    # ── Stage 4c: Presidio NER — semantic PII (names, DOB, IBAN, medical) ────
    # ML-NER + 40+ international PII types + deterministic validators.
    # Graceful degradation: no-op when presidio-analyzer not installed.
    if presidio_available():
        presidio_findings = await asyncio.get_event_loop().run_in_executor(
            None, presidio_scan, text
        )
        if presidio_findings:
            scan.merge_structural(presidio_findings)

    # ── Stage 5: CVSS-grounded risk scoring ──────────────────────────────────
    if scan.pii_types:
        cvss_score, cvss_level, _ = score_findings(scan.pii_types)
        # Use the higher of regex-derived score and CVSS score for accuracy
        final_risk_score = max(scan.risk_score, cvss_score)
        final_severity   = severity_from_level(cvss_level)
    else:
        final_risk_score = scan.risk_score
        final_severity   = scan.severity

    # ── Stage 6: Correlation — dedup and pattern elevation ───────────────────
    # org_id already extracted at top of function
    _is_dup, final_risk_score, corr_count = correlate(org_id, scan.pii_types, final_risk_score)

    # ── Stage 6b: Behavioral analysis — velocity / exfiltration / scanning ───
    text_len = len(text)
    analyzer = get_analyzer()
    anomaly  = analyzer.observe_and_analyse(org_id, scan.pii_types, text_len)
    if anomaly.is_anomalous:
        behavioral_lift  = anomaly.composite_score * 20.0
        final_risk_score = min(100.0, final_risk_score + behavioral_lift)

    # ── Stage 6c: Isolation Forest — org-specific learned anomaly score ───────
    # Queries the same backend events used by behavioral analysis.
    iforest      = get_anomaly_detector()
    vel_events   = analyzer._backend.query(f"behavioral:{org_id}", 60.0)
    exfil_events = analyzer._backend.query(f"behavioral:{org_id}", 600.0)
    iforest_score = iforest.observe(org_id, vel_events, exfil_events)
    if iforest_score > 0.7:
        # Only apply when well above the normal band (> 70th percentile anomaly)
        final_risk_score = min(100.0, final_risk_score + iforest_score * 15.0)

    # ── Stage 7: Policy engine (workspace-isolated) ───────────────────────────
    workspace_id = req.metadata.get("workspace_id", "default")
    ws = workspace_registry.get(str(workspace_id))
    active_policy = ws.policy_engine

    policy_result = active_policy.evaluate(
        pii_types=scan.pii_types,
        risk_score=final_risk_score,
        severity=final_severity,
        user_role=req.user_role,
        model=req.model,
        metadata=req.metadata,
    )

    # ── Stage 8: Tokenize / Redact ────────────────────────────────────────────
    # "redact" action: use cryptographic tokenization instead of tombstones.
    # The tokenizer vaults the original values and returns reversible tokens
    # (tsm_tok_*) so the LLM sees opaque placeholders.  The proxy calls
    # POST /detokenize with the LLM response to restore the original values.
    #
    # "route_local": data stays on-prem — still tokenize for audit-trail hygiene.
    # "block": no forwarding, no tokenization needed.
    vault_id: str | None = None
    redacted_body = dict(req.model_dump())
    if policy_result.action in ("redact", "route_local"):
        tokenizer = get_tokenizer()
        # Collect span-based findings for precise tokenization
        span_findings = [f for f in scan.raw_findings if "start" in f and "end" in f]
        if span_findings:
            # Tokenize the full concatenated text then rebuild per-message
            tokenized_text, vault_id = tokenizer.tokenize(text, span_findings)
            redacted_body = _tokenize_body_messages(req, tokenizer, scan.raw_findings)
        else:
            # Fall back to regex-based sanitizer when no span info
            redacted_body = _redact_body_messages(req)

    latency = (time.time() - t0) * 1000
    # request_id already extracted at top of function

    # ── Metrics ────────────────────────────────────────────────────────────────
    _metrics.record(policy_result.action, latency)

    # ── Audit log ──────────────────────────────────────────────────────────────
    _write_audit({
        "ts":         time.time(),
        "request_id": request_id,
        "org_id":     org_id,
        "model":      req.model,
        "action":     policy_result.action,
        "pii_types":  scan.pii_types,
        "risk_score": round(final_risk_score, 2),
        "severity":   final_severity,
        "rule":       policy_result.rule_name,
        "latency_ms": round(latency, 2),
    })

    # Fire webhook for critical events (non-blocking)
    if policy_result.action in ("block", "route_local") or final_risk_score >= 80:
        await alert_if_critical(
            pii_types=scan.pii_types,
            risk_score=final_risk_score,
            severity=final_severity,
            model=req.model,
            request_id=request_id,
        )

    response = DetectResponse(
        risk_score          = final_risk_score,
        action              = policy_result.action,
        pii_types           = scan.pii_types,
        severity            = final_severity,
        redacted_body       = redacted_body,
        findings            = [Finding(**{k: v for k, v in f.items()
                                         if k in ("type","severity","context","redacted")})
                               for f in scan.raw_findings],
        policy_rule         = policy_result.rule_name,
        latency_ms          = round(latency, 2),
        vault_id            = vault_id,
        presidio_available  = presidio_available(),
    )

    # ── OTel span (non-blocking, no-op when OTel not installed) ───────────────
    with trace_detect_call(org_id, req.model, policy_result.action,
                           scan.pii_types, final_risk_score, latency):
        pass  # span context set; attributes already attached inside helper

    return response


def _tokenize_body_messages(req: DetectRequest, tokenizer, findings: list[dict]) -> dict[str, Any]:
    """
    Rebuild the request body with each user message content tokenized.
    Returns the tokenized body dict (vault_id is tracked inside tokenizer).
    """
    body = req.model_dump()
    new_messages = []
    for m in req.messages:
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            # Find findings with span info for this message
            span_f = [f for f in findings if "start" in f and "end" in f]
            if span_f:
                tokenized, _ = tokenizer.tokenize(m["content"], span_f)
            else:
                san = sanitizer.sanitize(m["content"])
                tokenized = san.sanitized_text
            new_messages.append({**m, "content": tokenized})
        else:
            new_messages.append(m)
    body["messages"] = new_messages
    if req.prompt:
        span_f = [f for f in findings if "start" in f and "end" in f]
        if span_f:
            tokenized_prompt, _ = tokenizer.tokenize(req.prompt, span_f)
        else:
            san = sanitizer.sanitize(req.prompt)
            tokenized_prompt = san.sanitized_text
        body["prompt"] = tokenized_prompt
    return body


def _redact_body_messages(req: DetectRequest) -> dict[str, Any]:
    """
    Rebuild the request body with each user message independently sanitized.

    Previous bug: sanitize(join(all_user_msgs)) → apply to EACH message.
    This replaced every message with the entire joined corpus, which is wrong
    when there are multiple user messages (multi-turn conversations).

    Fix: sanitize each user message content individually.
    """
    body = req.model_dump()
    new_messages = []
    for m in req.messages:
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            san = sanitizer.sanitize(m["content"])
            new_messages.append({**m, "content": san.sanitized_text})
        else:
            new_messages.append(m)
    body["messages"] = new_messages
    if req.prompt:
        san = sanitizer.sanitize(req.prompt)
        body["prompt"] = san.sanitized_text
    return body


@app.post("/scan-response", response_model=ScanResponseResult)
async def scan_response(req: ScanResponseRequest):
    """
    Scan an AI model's response for PII leakage, prompt injection vectors,
    bypass acknowledgements, hallucinated credentials, and training data leakage.

    Two complementary passes:
      1. OutputInspector — specialised post-inference checks (bypass ack,
         credential hallucination, injection vectors, verbatim training data)
      2. Multi-stage classifier — same PII/NER/CVSS pipeline as /detect
         (catches personal data in AI responses)

    Enterprise use case: intercept AI responses before they reach the user;
    block or redact if the model outputted sensitive information.
    """
    t0 = time.time()

    # ── Pass 1: Output inspector (post-inference specialised checks) ──────────
    # These checks are unique to AI responses (not applicable to user prompts).
    # OutputInspectResult.threat: THREAT_NONE | BYPASS_ACKNOWLEDGEMENT | CREDENTIAL | etc.
    insp: OutputInspectResult = await asyncio.get_event_loop().run_in_executor(
        None,
        output_inspector.inspect,
        req.response_text,
        {"request_id": req.request_id or "unknown"},
    )

    _BLOCK_THREATS = {"bypass_acknowledgement", "credential_hallucination", "prompt_injection"}
    insp_is_block = insp.threat in _BLOCK_THREATS or (insp.risk_score >= 90 and insp.redacted is None)
    insp_pii_types = [insp.technique] if insp.technique else []

    # If the output inspector found a serious issue, short-circuit with block.
    if insp_is_block:
        latency = (time.time() - t0) * 1000
        return ScanResponseResult(
            pii_found=True,
            pii_types=insp_pii_types or [insp.threat],
            risk_score=insp.risk_score,
            severity="critical",
            redacted_text=insp.redacted or req.response_text,
            findings=[Finding(
                type=insp.threat, severity="critical",
                context=insp.evidence[:200], redacted=True,
            )],
            latency_ms=round(latency, 2),
        )

    # ── Pass 2: PII scan on the response text ─────────────────────────────────
    scan = classifier.scan(req.response_text)

    # Structural scan (JWTs, high-entropy tokens in response)
    structural = classifier.structural_scan(req.response_text)
    scan.merge_structural(structural)

    # NER scan for prose PII in response
    ner = classifier.ner_scan(req.response_text)
    if ner:
        scan.merge_structural(ner)

    # Merge any tags the output inspector surfaced
    for t in insp_pii_types:
        if t and t not in scan.pii_types:
            scan.pii_types.append(t)

    # CVSS scoring
    if scan.pii_types:
        cvss_score, cvss_level, _ = score_findings(scan.pii_types)
        final_risk = max(scan.risk_score, cvss_score, insp.risk_score)
        final_sev  = severity_from_level(cvss_level)
    else:
        final_risk = max(scan.risk_score, insp.risk_score)
        final_sev  = scan.severity

    # Redact PII from response text
    san = sanitizer.sanitize(req.response_text)
    redacted = insp.redacted if insp.redacted else san.sanitized_text

    latency = (time.time() - t0) * 1000

    return ScanResponseResult(
        pii_found=len(scan.pii_types) > 0,
        pii_types=scan.pii_types,
        risk_score=final_risk,
        severity=final_sev,
        redacted_text=redacted,
        findings=[Finding(**f) for f in scan.raw_findings],
        latency_ms=round(latency, 2),
    )


# ── Detokenize endpoint ───────────────────────────────────────────────────────

class DetokenizeRequest(BaseModel):
    """Restore original PII values in an LLM response."""
    text:     str
    vault_id: str | None = None

class DetokenizeResponse(BaseModel):
    restored_text: str
    restorations:  list[dict]   # [{"token": str, "pii_type": str, "restored": bool}]

@app.post("/detokenize", response_model=DetokenizeResponse)
async def detokenize(req: DetokenizeRequest):
    """
    Swap tsm_tok_* tokens in an LLM response back to the original PII values.

    The proxy calls this after receiving the LLM response for any request where
    /detect returned a non-null vault_id.  Tokens that have expired or are
    unknown are left in-place (so the caller always gets a usable response).
    """
    tokenizer = get_tokenizer()
    restored, restorations = tokenizer.detokenize(req.text, req.vault_id)
    return DetokenizeResponse(restored_text=restored, restorations=restorations)


@app.get("/rules")
def get_rules():
    return {"rules": policy_engine.rules_as_dict()}

@app.post("/rules")
def add_rule(req: RuleRequest):
    rule = PolicyRule(
        name=req.name,
        condition=req.condition,
        action=req.action,
        priority=req.priority,
    )
    policy_engine.add_rule(rule)
    return {"status": "ok", "rule": req.name}

@app.delete("/rules/{name}")
def delete_rule(name: str):
    removed = policy_engine.remove_rule(name)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Rule '{name}' not found")
    return {"status": "ok"}


# ── Workspace management ───────────────────────────────────────────────────────

class WorkspaceRequest(BaseModel):
    org_id:              str
    name:                str
    rate_limit:          int = 100
    compliance_framework: str | None = None  # gdpr | hipaa | soc2 | pci_dss

@app.get("/workspaces")
def list_workspaces():
    return {"workspaces": workspace_registry.list_all()}

@app.post("/workspaces/{workspace_id}")
def create_workspace(workspace_id: str, req: WorkspaceRequest):
    ws = workspace_registry.create(workspace_id, req.org_id, req.name, req.rate_limit)
    added_rules: list[str] = []
    if req.compliance_framework:
        added_rules = ws.policy_engine.load_compliance_framework(req.compliance_framework)
    return {
        "status":    "ok",
        "workspace": ws.to_dict(),
        "compliance_framework": req.compliance_framework,
        "rules_loaded": added_rules,
    }

@app.delete("/workspaces/{workspace_id}")
def delete_workspace(workspace_id: str):
    removed = workspace_registry.delete(workspace_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Workspace '{workspace_id}' not found or is default")
    return {"status": "ok"}

@app.get("/workspaces/{workspace_id}/rules")
def get_workspace_rules(workspace_id: str):
    ws = workspace_registry.get(workspace_id)
    return {"rules": ws.policy_engine.rules_as_dict()}

@app.post("/workspaces/{workspace_id}/rules")
def add_workspace_rule(workspace_id: str, req: RuleRequest):
    ws   = workspace_registry.get(workspace_id)
    rule = PolicyRule(name=req.name, condition=req.condition, action=req.action, priority=req.priority)
    ws.policy_engine.add_rule(rule)
    return {"status": "ok", "rule": req.name, "workspace": workspace_id}

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("DETECTOR_PORT", 8001)), log_level="warning")
