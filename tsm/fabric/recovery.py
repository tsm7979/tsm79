"""
TSM Fabric — Recovery Engine
============================
"What happens if everything breaks?" — the autonomous recovery loop that few
security products bother to build:

    threat → assessment → isolation → recovery → validation → return to service

For predefined events this runs with **no human intervention**. The fail-safe
rule: if any stage's handler fails (returns false *or* raises), the engine does
not loop or pretend success — it **escalates to a human** and leaves the incident
in a safe, isolated state. Automation that can't fix it must hand off, not guess.

Handlers are pluggable callables; defaults are safe no-ops so the loop is fully
functional out of the box and you override the stages with real actions. Each
transition is timestamped and (optionally) audited. Pure standard library.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, List, Optional, Tuple


class RecoveryStage(str, Enum):
    DETECTED = "detected"
    ASSESSED = "assessed"
    ISOLATED = "isolated"
    RECOVERING = "recovering"
    VALIDATING = "validating"
    RESTORED = "restored"
    ESCALATED = "escalated"


@dataclass(frozen=True)
class Transition:
    stage: RecoveryStage
    ok: bool
    detail: str
    ts: float

    def as_dict(self) -> dict:
        return {"stage": self.stage.value, "ok": self.ok, "detail": self.detail, "ts": self.ts}


@dataclass
class Incident:
    id: str
    threat: str
    severity: str
    subject: str
    stage: RecoveryStage
    transitions: List[Transition] = field(default_factory=list)
    resolved: bool = False
    escalated: bool = False

    @property
    def stages(self) -> Tuple[str, ...]:
        return tuple(t.stage.value for t in self.transitions)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "threat": self.threat, "severity": self.severity,
            "subject": self.subject, "stage": self.stage.value,
            "resolved": self.resolved, "escalated": self.escalated,
            "timeline": [t.as_dict() for t in self.transitions],
        }


# Handler signatures: assessor(incident)->severity str; the rest ->bool (success).
Assessor = Callable[[Incident], Any]
StageHandler = Callable[[Incident], bool]

_DEFAULT_AUTO = ("high", "critical")


class RecoveryEngine:
    def __init__(
        self,
        *,
        assessor: Optional[Assessor] = None,
        isolator: Optional[StageHandler] = None,
        recoverer: Optional[StageHandler] = None,
        validator: Optional[StageHandler] = None,
        audit: Optional[Callable[[dict], None]] = None,
        auto_isolate: Tuple[str, ...] = _DEFAULT_AUTO,
    ) -> None:
        self._assessor = assessor
        self._isolator = isolator
        self._recoverer = recoverer
        self._validator = validator
        self._audit = audit
        self._auto = tuple(s.lower() for s in auto_isolate)

    def handle(self, threat: str, *, severity: str = "high", subject: str = "") -> Incident:
        inc = Incident(id=uuid.uuid4().hex, threat=threat, severity=severity,
                       subject=subject, stage=RecoveryStage.DETECTED)
        self._record(inc, RecoveryStage.DETECTED, True, f"threat detected: {threat}")

        # ── assessment ──────────────────────────────────────────────────────
        sev = severity
        try:
            if self._assessor is not None:
                sev = str(self._assessor(inc)) or severity
        except Exception as exc:
            return self._escalate(inc, RecoveryStage.ASSESSED, f"assessment failed: {exc}")
        inc.severity = sev
        self._record(inc, RecoveryStage.ASSESSED, True, f"severity assessed: {sev}")

        # Low severity → monitor only, no isolation/recovery needed.
        if sev.lower() not in self._auto:
            inc.resolved = True
            self._record(inc, RecoveryStage.RESTORED, True,
                         "low severity — monitored, no isolation required")
            return inc

        # ── isolation → recovery → validation ───────────────────────────────
        for stage, handler, failmsg in (
            (RecoveryStage.ISOLATED, self._isolator, "isolation failed"),
            (RecoveryStage.RECOVERING, self._recoverer, "recovery failed"),
            (RecoveryStage.VALIDATING, self._validator, "validation failed"),
        ):
            try:
                ok = True if handler is None else bool(handler(inc))
            except Exception as exc:
                return self._escalate(inc, stage, f"{failmsg}: {exc}")
            if not ok:
                return self._escalate(inc, stage, failmsg)
            self._record(inc, stage, True, f"{stage.value}: ok")

        inc.resolved = True
        self._record(inc, RecoveryStage.RESTORED, True, "validated — returned to service")
        return inc

    # ── internals ───────────────────────────────────────────────────────────

    def _escalate(self, inc: Incident, stage: RecoveryStage, detail: str) -> Incident:
        self._record(inc, stage, False, detail)
        inc.escalated = True
        inc.resolved = False
        self._record(inc, RecoveryStage.ESCALATED, True,
                     "handed to human — autonomous recovery could not complete safely")
        return inc

    def _record(self, inc: Incident, stage: RecoveryStage, ok: bool, detail: str) -> None:
        transition = Transition(stage=stage, ok=ok, detail=detail, ts=time.time())
        inc.transitions.append(transition)
        inc.stage = stage
        if self._audit is not None:
            try:
                self._audit({"incident": inc.id, **transition.as_dict()})
            except Exception:
                pass  # auditing must never break recovery
