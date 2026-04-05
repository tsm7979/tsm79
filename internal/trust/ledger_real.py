"""
Trust & Evidence Ledger

Local, immutable audit trail for all security operations.
Implements Step 10 of the data-resident workflow.

All evidence stays local:
- Findings
- Fixes
- Verifications
- Compliance evidence

This is the source of truth for audits.
"""

from __future__ import annotations

import uuid
import json
import hashlib
import logging
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class EntryType(str, Enum):
    """Types of ledger entries."""
    
    FINDING = "finding"
    FIX_PROPOSAL = "fix_proposal"
    APPROVAL = "approval"
    EXECUTION = "execution"
    VERIFICATION = "verification"
    ROLLBACK = "rollback"
    POLICY_CHECK = "policy_check"
    COMPLIANCE_EVIDENCE = "compliance_evidence"


class VerificationStatus(str, Enum):
    """Verification status."""
    
    PASSED = "passed"
    FAILED = "failed"
    PENDING = "pending"
    SKIPPED = "skipped"


@dataclass
class LedgerEntry:
    """
    An immutable entry in the trust ledger.
    
    Each entry is cryptographically linked to the previous,
    creating an auditable chain of evidence.
    
    Attributes:
        id: Unique entry identifier
        entry_type: Type of entry
        timestamp: When the entry was created
        actor: Who/what created this entry
        action: What action was taken
        resource_id: Affected resource
        data: Entry data (sanitized)
        previous_hash: Hash of the previous entry
        hash: This entry's hash
        signatures: Digital signatures
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entry_type: EntryType = EntryType.FINDING
    timestamp: datetime = field(default_factory=datetime.now)
    actor: str = ""
    action: str = ""
    resource_id: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    previous_hash: str = ""
    hash: str = ""
    signatures: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate hash after initialization."""
        if not self.hash:
            self.hash = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate cryptographic hash of this entry."""
        content = json.dumps({
            "id": self.id,
            "entry_type": self.entry_type.value,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "resource_id": self.resource_id,
            "data": self.data,
            "previous_hash": self.previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def verify(self) -> bool:
        """Verify the entry's integrity."""
        return self.hash == self._calculate_hash()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "entry_type": self.entry_type.value,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "resource_id": self.resource_id,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ComplianceEvidence:
    """
    Compliance evidence record.
    
    Links findings, fixes, and verifications
    to compliance requirements.
    
    Attributes:
        id: Evidence identifier
        framework: Compliance framework (SOC2, HIPAA, etc.)
        requirement_id: Specific requirement
        finding_id: Related finding
        fix_id: Related fix
        verification_id: Related verification
        status: Compliance status
        evidence_data: Supporting evidence
    """
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    framework: str = ""
    requirement_id: str = ""
    finding_id: Optional[str] = None
    fix_id: Optional[str] = None
    verification_id: Optional[str] = None
    status: str = "pending"
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "framework": self.framework,
            "requirement_id": self.requirement_id,
            "finding_id": self.finding_id,
            "fix_id": self.fix_id,
            "verification_id": self.verification_id,
            "status": self.status,
            "evidence_data": self.evidence_data,
            "created_at": self.created_at.isoformat(),
        }


class TrustLedger(BaseModel):
    """
    Local trust ledger for audit trail.
    
    Stores all security operations with cryptographic integrity.
    Everything stays local - this is the enterprise audit source.
    
    Attributes:
        name: Ledger identifier
        storage_path: Where to persist the ledger
        auto_persist: Automatically save to disk
        max_entries_memory: Max entries to keep in memory
    """
    
    model_config = {"arbitrary_types_allowed": True}
    
    name: str = Field(default="trust_ledger")
    storage_path: Optional[str] = Field(default=None)
    auto_persist: bool = Field(default=True)
    max_entries_memory: int = Field(default=10000)
    
    on_entry_added: Optional[Callable[[LedgerEntry], None]] = Field(default=None)
    
    _entries: List[LedgerEntry] = []
    _compliance_evidence: List[ComplianceEvidence] = []
    _genesis_hash: str = ""
    
    def __init__(self, **data: Any):
        super().__init__(**data)
        self._entries = []
        self._compliance_evidence = []
        self._genesis_hash = hashlib.sha256(b"genesis").hexdigest()
        
        # Load from disk if exists
        if self.storage_path:
            self._load()
    
    def append(
        self,
        entry_type: EntryType,
        actor: str,
        action: str,
        resource_id: str = "",
        data: Optional[Dict[str, Any]] = None,
    ) -> LedgerEntry:
        """
        Append a new entry to the ledger.
        
        Args:
            entry_type: Type of entry
            actor: Who/what created this
            action: What action was taken
            resource_id: Affected resource
            data: Entry data
            
        Returns:
            The created LedgerEntry
        """
        previous_hash = self._get_last_hash()
        
        entry = LedgerEntry(
            entry_type=entry_type,
            actor=actor,
            action=action,
            resource_id=resource_id,
            data=data or {},
            previous_hash=previous_hash,
        )
        
        self._entries.append(entry)
        
        # Trim if too many in memory
        if len(self._entries) > self.max_entries_memory:
            self._entries = self._entries[-self.max_entries_memory:]
        
        if self.auto_persist and self.storage_path:
            self._persist_entry(entry)
        
        if self.on_entry_added:
            self.on_entry_added(entry)
        
        logger.debug(f"Ledger entry: {entry_type.value} by {actor}")
        
        return entry
    
    def _get_last_hash(self) -> str:
        """Get the hash of the last entry."""
        if not self._entries:
            return self._genesis_hash
        return self._entries[-1].hash
    
    def log_finding(
        self,
        finding_id: str,
        finding_type: str,
        severity: str,
        resource: str,
        detector: str = "system",
    ) -> LedgerEntry:
        """Log a security finding."""
        return self.append(
            entry_type=EntryType.FINDING,
            actor=detector,
            action="finding_detected",
            resource_id=finding_id,
            data={
                "finding_type": finding_type,
                "severity": severity,
                "resource": resource,
            }
        )
    
    def log_fix_proposal(
        self,
        fix_id: str,
        finding_id: str,
        description: str,
        proposer: str = "system",
    ) -> LedgerEntry:
        """Log a fix proposal."""
        return self.append(
            entry_type=EntryType.FIX_PROPOSAL,
            actor=proposer,
            action="fix_proposed",
            resource_id=fix_id,
            data={
                "finding_id": finding_id,
                "description": description,
            }
        )
    
    def log_approval(
        self,
        approval_id: str,
        fix_id: str,
        approved: bool,
        approver: str,
        reason: Optional[str] = None,
    ) -> LedgerEntry:
        """Log an approval decision."""
        return self.append(
            entry_type=EntryType.APPROVAL,
            actor=approver,
            action="approved" if approved else "rejected",
            resource_id=approval_id,
            data={
                "fix_id": fix_id,
                "approved": approved,
                "reason": reason,
            }
        )
    
    def log_execution(
        self,
        execution_id: str,
        fix_id: str,
        status: str,
        executor: str = "system",
        details: Optional[Dict[str, Any]] = None,
    ) -> LedgerEntry:
        """Log an execution."""
        return self.append(
            entry_type=EntryType.EXECUTION,
            actor=executor,
            action=f"executed_{status}",
            resource_id=execution_id,
            data={
                "fix_id": fix_id,
                "status": status,
                "details": details or {},
            }
        )
    
    def log_verification(
        self,
        verification_id: str,
        execution_id: str,
        status: VerificationStatus,
        checks: List[str],
        verifier: str = "system",
    ) -> LedgerEntry:
        """Log a verification result."""
        return self.append(
            entry_type=EntryType.VERIFICATION,
            actor=verifier,
            action=f"verified_{status.value}",
            resource_id=verification_id,
            data={
                "execution_id": execution_id,
                "status": status.value,
                "checks": checks,
            }
        )
    
    def add_compliance_evidence(
        self,
        framework: str,
        requirement_id: str,
        finding_id: Optional[str] = None,
        fix_id: Optional[str] = None,
        verification_id: Optional[str] = None,
        evidence_data: Optional[Dict[str, Any]] = None,
    ) -> ComplianceEvidence:
        """Add compliance evidence linking finding, fix, and verification."""
        evidence = ComplianceEvidence(
            framework=framework,
            requirement_id=requirement_id,
            finding_id=finding_id,
            fix_id=fix_id,
            verification_id=verification_id,
            status="complete" if verification_id else "in_progress",
            evidence_data=evidence_data or {},
        )
        
        self._compliance_evidence.append(evidence)
        
        # Also log to ledger
        self.append(
            entry_type=EntryType.COMPLIANCE_EVIDENCE,
            actor="compliance_engine",
            action="evidence_recorded",
            resource_id=evidence.id,
            data=evidence.to_dict(),
        )
        
        return evidence
    
    def verify_chain(self) -> bool:
        """Verify the integrity of the entire ledger chain."""
        if not self._entries:
            return True
        
        # Check genesis
        if self._entries[0].previous_hash != self._genesis_hash:
            logger.error("Genesis hash mismatch")
            return False
        
        # Verify each entry
        for i, entry in enumerate(self._entries):
            if not entry.verify():
                logger.error(f"Entry {entry.id} hash mismatch")
                return False
            
            if i > 0 and entry.previous_hash != self._entries[i-1].hash:
                logger.error(f"Chain broken at entry {entry.id}")
                return False
        
        return True
    
    def get_entries(
        self,
        entry_type: Optional[EntryType] = None,
        actor: Optional[str] = None,
        resource_id: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[LedgerEntry]:
        """Query ledger entries."""
        entries = self._entries
        
        if entry_type:
            entries = [e for e in entries if e.entry_type == entry_type]
        if actor:
            entries = [e for e in entries if e.actor == actor]
        if resource_id:
            entries = [e for e in entries if e.resource_id == resource_id]
        if since:
            entries = [e for e in entries if e.timestamp >= since]
        
        return entries[-limit:]
    
    def get_compliance_evidence(
        self,
        framework: Optional[str] = None,
    ) -> List[ComplianceEvidence]:
        """Get compliance evidence records."""
        evidence = self._compliance_evidence
        
        if framework:
            evidence = [e for e in evidence if e.framework == framework]
        
        return evidence
    
    def generate_audit_report(
        self,
        since: Optional[datetime] = None,
        framework: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate an audit report."""
        entries = self.get_entries(since=since)
        evidence = self.get_compliance_evidence(framework=framework)
        
        return {
            "generated_at": datetime.now().isoformat(),
            "chain_valid": self.verify_chain(),
            "total_entries": len(entries),
            "entries_by_type": {
                t.value: len([e for e in entries if e.entry_type == t])
                for t in EntryType
            },
            "compliance_evidence_count": len(evidence),
            "frameworks_covered": list(set(e.framework for e in evidence)),
            "sample_entries": [e.to_dict() for e in entries[-10:]],
        }
    
    def _persist_entry(self, entry: LedgerEntry) -> None:
        """Persist a single entry to disk."""
        if not self.storage_path:
            return
        
        path = Path(self.storage_path)
        path.mkdir(parents=True, exist_ok=True)
        
        ledger_file = path / "ledger.jsonl"
        with open(ledger_file, "a") as f:
            f.write(entry.to_json() + "\n")
    
    def _load(self) -> None:
        """Load ledger from disk."""
        if not self.storage_path:
            return
        
        ledger_file = Path(self.storage_path) / "ledger.jsonl"
        
        if not ledger_file.exists():
            return
        
        try:
            with open(ledger_file) as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        entry = LedgerEntry(
                            id=data["id"],
                            entry_type=EntryType(data["entry_type"]),
                            timestamp=datetime.fromisoformat(data["timestamp"]),
                            actor=data["actor"],
                            action=data["action"],
                            resource_id=data["resource_id"],
                            data=data["data"],
                            previous_hash=data["previous_hash"],
                            hash=data["hash"],
                        )
                        self._entries.append(entry)
            
            logger.info(f"Loaded {len(self._entries)} ledger entries")
        except Exception as e:
            logger.error(f"Failed to load ledger: {e}")
    
    def export(self, format: str = "json") -> str:
        """Export the ledger."""
        if format == "json":
            return json.dumps({
                "name": self.name,
                "entries": [e.to_dict() for e in self._entries],
                "evidence": [e.to_dict() for e in self._compliance_evidence],
            }, indent=2)
        
        raise ValueError(f"Unknown format: {format}")
