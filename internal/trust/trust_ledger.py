# backend/src/core/agentic/trust_ledger.py

"""
Trust & Evidence Ledger - Layer 10

Proves trust continuously:
- What was detected
- What was fixed
- When it was verified
- Current trust posture

This is the compliance goldmine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


class TrustState(str, Enum):
    """Trust state of the system."""
    GREEN = "green"     # All verified, no issues
    YELLOW = "yellow"   # Pending fixes or verifications
    RED = "red"         # Failed verifications or critical issues
    UNKNOWN = "unknown" # Insufficient data


class EvidenceType(str, Enum):
    """Types of compliance evidence."""
    DETECTION = "detection"
    FIX_APPLIED = "fix_applied"
    VERIFICATION = "verification"
    APPROVAL = "approval"
    REGRESSION = "regression"
    POLICY_COMPLIANCE = "policy_compliance"


@dataclass
class EvidenceRecord:
    """A record of compliance evidence."""
    
    id: str
    evidence_type: EvidenceType
    category: str  # e.g., "security", "compliance", "reliability"
    title: str
    description: str
    finding_id: Optional[str]
    execution_id: Optional[str]
    verification_id: Optional[str]
    outcome: str  # "pass", "fail", "pending"
    timestamp: datetime
    org_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "evidence_type": self.evidence_type.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "finding_id": self.finding_id,
            "execution_id": self.execution_id,
            "verification_id": self.verification_id,
            "outcome": self.outcome,
            "timestamp": self.timestamp.isoformat(),
            "org_id": self.org_id,
            "metadata": self.metadata,
        }


@dataclass
class TrustReport:
    """Current trust posture report."""
    
    id: str
    org_id: Optional[str]
    state: TrustState
    generated_at: datetime
    open_findings: int
    pending_fixes: int
    pending_verifications: int
    passed_verifications_24h: int
    failed_verifications_24h: int
    compliance_score: float  # 0.0 to 1.0
    categories: Dict[str, TrustState]
    recommendations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "state": self.state.value,
            "generated_at": self.generated_at.isoformat(),
            "open_findings": self.open_findings,
            "pending_fixes": self.pending_fixes,
            "pending_verifications": self.pending_verifications,
            "passed_verifications_24h": self.passed_verifications_24h,
            "failed_verifications_24h": self.failed_verifications_24h,
            "compliance_score": self.compliance_score,
            "categories": {k: v.value for k, v in self.categories.items()},
            "recommendations": self.recommendations,
        }


class TrustLedger:
    """
    Maintains continuous trust evidence.
    
    Key principle: Prove trust, don't assume it.
    """
    
    def __init__(self):
        self._evidence: List[EvidenceRecord] = []
        self._trust_state: TrustState = TrustState.UNKNOWN
        self._category_states: Dict[str, TrustState] = {}
        logger.info("TrustLedger initialized")
    
    async def record_detection(
        self,
        finding_id: str,
        title: str,
        category: str,
        severity: str,
        org_id: Optional[str] = None,
    ) -> EvidenceRecord:
        """Record a detection event."""
        record = EvidenceRecord(
            id=str(uuid4()),
            evidence_type=EvidenceType.DETECTION,
            category=category,
            title=title,
            description=f"Detected: {title}",
            finding_id=finding_id,
            execution_id=None,
            verification_id=None,
            outcome="pending",
            timestamp=datetime.utcnow(),
            org_id=org_id,
            metadata={"severity": severity},
        )
        
        self._evidence.append(record)
        self._update_trust_state()
        
        logger.info(f"Recorded detection: {finding_id}")
        return record
    
    async def record_fix(
        self,
        finding_id: str,
        execution_id: str,
        title: str,
        category: str,
        success: bool,
        org_id: Optional[str] = None,
    ) -> EvidenceRecord:
        """Record a fix application."""
        record = EvidenceRecord(
            id=str(uuid4()),
            evidence_type=EvidenceType.FIX_APPLIED,
            category=category,
            title=f"Fix applied: {title}",
            description=f"Fix for finding {finding_id}",
            finding_id=finding_id,
            execution_id=execution_id,
            verification_id=None,
            outcome="pass" if success else "fail",
            timestamp=datetime.utcnow(),
            org_id=org_id,
        )
        
        self._evidence.append(record)
        self._update_trust_state()
        
        logger.info(f"Recorded fix: {execution_id}")
        return record
    
    async def record_verification(
        self,
        verification_id: str,
        finding_id: Optional[str],
        execution_id: str,
        category: str,
        passed: bool,
        org_id: Optional[str] = None,
    ) -> EvidenceRecord:
        """Record a verification result."""
        record = EvidenceRecord(
            id=str(uuid4()),
            evidence_type=EvidenceType.VERIFICATION,
            category=category,
            title="Verification " + ("passed" if passed else "failed"),
            description=f"Verification for execution {execution_id}",
            finding_id=finding_id,
            execution_id=execution_id,
            verification_id=verification_id,
            outcome="pass" if passed else "fail",
            timestamp=datetime.utcnow(),
            org_id=org_id,
        )
        
        self._evidence.append(record)
        self._update_trust_state()
        
        logger.info(
            f"Recorded verification: {verification_id} "
            f"({'passed' if passed else 'failed'})"
        )
        return record
    
    async def record_approval(
        self,
        approval_id: str,
        action_title: str,
        approver: str,
        category: str,
        org_id: Optional[str] = None,
    ) -> EvidenceRecord:
        """Record an approval event."""
        record = EvidenceRecord(
            id=str(uuid4()),
            evidence_type=EvidenceType.APPROVAL,
            category=category,
            title=f"Approved: {action_title}",
            description=f"Approved by {approver}",
            finding_id=None,
            execution_id=None,
            verification_id=None,
            outcome="pass",
            timestamp=datetime.utcnow(),
            org_id=org_id,
            metadata={"approver": approver, "approval_id": approval_id},
        )
        
        self._evidence.append(record)
        return record
    
    def _update_trust_state(self) -> None:
        """Update overall trust state based on evidence."""
        now = datetime.utcnow()
        day_ago = now - timedelta(days=1)
        
        recent = [e for e in self._evidence if e.timestamp > day_ago]
        
        if not recent:
            self._trust_state = TrustState.UNKNOWN
            return
        
        # Count outcomes
        pending = sum(1 for e in recent if e.outcome == "pending")
        failed = sum(1 for e in recent if e.outcome == "fail")
        passed = sum(1 for e in recent if e.outcome == "pass")
        
        # Determine state
        if failed > 0:
            self._trust_state = TrustState.RED
        elif pending > passed:
            self._trust_state = TrustState.YELLOW
        elif passed > 0:
            self._trust_state = TrustState.GREEN
        else:
            self._trust_state = TrustState.UNKNOWN
        
        # Update category states
        categories = set(e.category for e in recent)
        for cat in categories:
            cat_evidence = [e for e in recent if e.category == cat]
            cat_failed = any(e.outcome == "fail" for e in cat_evidence)
            cat_pending = any(e.outcome == "pending" for e in cat_evidence)
            
            if cat_failed:
                self._category_states[cat] = TrustState.RED
            elif cat_pending:
                self._category_states[cat] = TrustState.YELLOW
            else:
                self._category_states[cat] = TrustState.GREEN
    
    async def generate_report(
        self,
        org_id: Optional[str] = None,
    ) -> TrustReport:
        """Generate current trust posture report."""
        now = datetime.utcnow()
        day_ago = now - timedelta(days=1)
        
        # Filter by org if provided
        evidence = self._evidence
        if org_id:
            evidence = [e for e in evidence if e.org_id == org_id]
        
        recent = [e for e in evidence if e.timestamp > day_ago]
        
        # Count metrics
        open_findings = sum(
            1 for e in evidence
            if e.evidence_type == EvidenceType.DETECTION
            and e.outcome == "pending"
        )
        
        pending_fixes = sum(
            1 for e in evidence
            if e.evidence_type == EvidenceType.FIX_APPLIED
            and e.outcome == "pending"
        )
        
        pending_verifications = sum(
            1 for e in recent
            if e.evidence_type == EvidenceType.VERIFICATION
            and e.outcome == "pending"
        )
        
        passed_24h = sum(
            1 for e in recent
            if e.evidence_type == EvidenceType.VERIFICATION
            and e.outcome == "pass"
        )
        
        failed_24h = sum(
            1 for e in recent
            if e.evidence_type == EvidenceType.VERIFICATION
            and e.outcome == "fail"
        )
        
        # Calculate compliance score
        total_recent = len(recent)
        if total_recent > 0:
            passed_ratio = sum(
                1 for e in recent if e.outcome == "pass"
            ) / total_recent
        else:
            passed_ratio = 0.0
        
        # Generate recommendations
        recommendations = []
        if open_findings > 0:
            recommendations.append(
                f"Address {open_findings} open findings"
            )
        if failed_24h > 0:
            recommendations.append(
                f"Investigate {failed_24h} failed verifications"
            )
        if pending_verifications > 5:
            recommendations.append(
                "Run pending verifications to update trust state"
            )
        
        return TrustReport(
            id=str(uuid4()),
            org_id=org_id,
            state=self._trust_state,
            generated_at=now,
            open_findings=open_findings,
            pending_fixes=pending_fixes,
            pending_verifications=pending_verifications,
            passed_verifications_24h=passed_24h,
            failed_verifications_24h=failed_24h,
            compliance_score=passed_ratio,
            categories=self._category_states.copy(),
            recommendations=recommendations,
        )
    
    def get_evidence(
        self,
        org_id: Optional[str] = None,
        category: Optional[str] = None,
        evidence_type: Optional[EvidenceType] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[EvidenceRecord]:
        """Query evidence records."""
        records = self._evidence
        
        if org_id:
            records = [r for r in records if r.org_id == org_id]
        if category:
            records = [r for r in records if r.category == category]
        if evidence_type:
            records = [r for r in records if r.evidence_type == evidence_type]
        if since:
            records = [r for r in records if r.timestamp >= since]
        
        return sorted(
            records, key=lambda r: r.timestamp, reverse=True
        )[:limit]
    
    def get_trust_state(self) -> TrustState:
        """Get current trust state."""
        return self._trust_state
    
    def get_category_state(self, category: str) -> TrustState:
        """Get trust state for a category."""
        return self._category_states.get(category, TrustState.UNKNOWN)
    
    def get_compliance_timeline(
        self,
        days: int = 30,
        org_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get compliance score timeline."""
        now = datetime.utcnow()
        timeline = []
        
        for day_offset in range(days):
            day_start = now - timedelta(days=day_offset + 1)
            day_end = now - timedelta(days=day_offset)
            
            day_evidence = [
                e for e in self._evidence
                if day_start <= e.timestamp < day_end
                and (org_id is None or e.org_id == org_id)
            ]
            
            if day_evidence:
                passed = sum(1 for e in day_evidence if e.outcome == "pass")
                score = passed / len(day_evidence)
            else:
                score = None
            
            timeline.append({
                "date": day_start.date().isoformat(),
                "compliance_score": score,
                "evidence_count": len(day_evidence),
            })
        
        return timeline
