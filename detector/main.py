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

import os
import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any

# Ensure tsm package is importable (detector lives one level below repo root)
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root))

from detector.classifier import Classifier
from detector.policy_engine import PolicyEngine, PolicyRule
from detector.alerting import alert_if_critical
from detector.workspace import registry as workspace_registry
from detector.risk_scorer import score_findings, severity_from_level
from detector.sanitizer import Sanitizer
from detector.correlation import correlate, correlation_stats

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

classifier    = Classifier()
policy_engine = PolicyEngine()
sanitizer     = Sanitizer()

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

class RuleRequest(BaseModel):
    name: str
    condition: dict[str, Any]
    action: str
    priority: int = 100

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status":       "healthy",
        "service":      "TSM Detector",
        "version":      "2.0.0",
        "llm_assist":   bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")),
        "correlation":  correlation_stats(),
    }

@app.post("/detect", response_model=DetectResponse)
async def detect(req: DetectRequest):
    t0 = time.time()

    # Extract full text for analysis
    text = req.prompt or " ".join(
        m.get("content", "") for m in req.messages if m.get("role") == "user"
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
        scan.merge_structural(ner_findings)  # same merge path

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
    org_id = req.metadata.get("org_id", "default")
    _is_dup, final_risk_score, corr_count = correlate(org_id, scan.pii_types, final_risk_score)

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

    # ── Stage 8: Redact using centralized Sanitizer ───────────────────────────
    redacted_body = dict(req.model_dump())
    if policy_result.action in ("redact", "route_local"):
        san_result = sanitizer.sanitize(text)
        redacted_body = _redact_body(req, san_result.sanitized_text)

    latency    = (time.time() - t0) * 1000
    request_id = req.metadata.get("request_id", "unknown")

    # Fire webhook for critical events (non-blocking)
    if policy_result.action in ("block", "route_local") or final_risk_score >= 80:
        await alert_if_critical(
            pii_types=scan.pii_types,
            risk_score=final_risk_score,
            severity=final_severity,
            model=req.model,
            request_id=request_id,
        )

    return DetectResponse(
        risk_score   = final_risk_score,
        action       = policy_result.action,
        pii_types    = scan.pii_types,
        severity     = final_severity,
        redacted_body= redacted_body,
        findings     = [Finding(**f) for f in scan.raw_findings],
        policy_rule  = policy_result.rule_name,
        latency_ms   = round(latency, 2),
    )


def _redact_body(req: DetectRequest, redacted_text: str) -> dict[str, Any]:
    """Rebuild the request body with redacted user messages."""
    body = req.model_dump()
    new_messages = []
    for m in req.messages:
        if m.get("role") == "user":
            new_messages.append({**m, "content": redacted_text})
        else:
            new_messages.append(m)
    body["messages"] = new_messages
    if req.prompt:
        body["prompt"] = redacted_text
    return body


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
