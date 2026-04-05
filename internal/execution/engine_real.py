# backend/src/core/agentic/execution_engine.py

"""
Execution Engine - Layer 8

Does the work:
- Commit code
- Trigger workflows
- Apply infra changes
- Log every action

Full audit trail for compliance.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from gateway.action_executor import ActionExecutor, Action, ActionResult, ActionType
from gateway.approval_gates import ApprovalGate

logger = logging.getLogger(__name__)


class ExecutionStatus(str, Enum):
    """Status of an execution."""
    PENDING_APPROVAL = "pending_approval"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


@dataclass
class ExecutionRecord:
    """Record of an execution for audit trail."""
    
    id: str
    action: Action
    status: ExecutionStatus
    result: Optional[ActionResult]
    approval_id: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    org_id: Optional[str] = None
    initiated_by: str = "system"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action.to_dict(),
            "status": self.status.value,
            "result": self.result.to_dict() if self.result else None,
            "approval_id": self.approval_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat(),
            "org_id": self.org_id,
            "initiated_by": self.initiated_by,
            "metadata": self.metadata,
        }


class ExecutionEngine:
    """
    Orchestrates execution with approval and audit.
    
    Key responsibilities:
    - Queue actions for execution
    - Enforce approval gates
    - Execute via ActionExecutor
    - Maintain full audit trail
    """
    
    def __init__(
        self,
        executor: Optional[ActionExecutor] = None,
        approval_gate: Optional[ApprovalGate] = None,
    ):
        self._executor = executor or ActionExecutor()
        self._approval_gate = approval_gate or ApprovalGate()
        self._records: Dict[str, ExecutionRecord] = {}
        self._queue: List[str] = []
        logger.info("ExecutionEngine initialized")
    
    async def submit(
        self,
        action: Action,
        org_id: Optional[str] = None,
        initiated_by: str = "system",
        context: Optional[Dict[str, Any]] = None,
    ) -> ExecutionRecord:
        """
        Submit an action for execution.
        
        Will check approval gates and queue if needed.
        """
        record = ExecutionRecord(
            id=str(uuid4()),
            action=action,
            status=ExecutionStatus.QUEUED,
            result=None,
            approval_id=None,
            started_at=None,
            completed_at=None,
            created_at=datetime.utcnow(),
            org_id=org_id,
            initiated_by=initiated_by,
        )
        
        self._records[record.id] = record
        
        # Check approval
        approved, approval_id = await self._approval_gate.check_approval(
            agent_id=initiated_by,
            action=action,
            context=context or {},
        )
        
        if not approved:
            record.status = ExecutionStatus.PENDING_APPROVAL
            record.approval_id = approval_id
            logger.info(
                f"Execution {record.id} pending approval: {approval_id}"
            )
            return record
        
        # Auto-approved or low risk, queue for execution
        self._queue.append(record.id)
        logger.info(f"Execution {record.id} queued")
        
        return record
    
    async def execute_now(
        self,
        record_id: str,
    ) -> ExecutionRecord:
        """
        Execute a queued action immediately.
        
        Bypasses queue but still requires approval.
        """
        record = self._records.get(record_id)
        if not record:
            raise ValueError(f"Execution record not found: {record_id}")
        
        # Check if pending approval
        if record.status == ExecutionStatus.PENDING_APPROVAL:
            is_approved = await self._approval_gate.is_approved(record.approval_id)
            if not is_approved:
                raise ValueError(
                    f"Execution {record_id} pending approval: {record.approval_id}"
                )
        
        # Execute
        record.status = ExecutionStatus.RUNNING
        record.started_at = datetime.utcnow()
        
        try:
            result = await self._executor.execute(record.action)
            
            record.result = result
            record.status = (
                ExecutionStatus.COMPLETED if result.success
                else ExecutionStatus.FAILED
            )
            record.completed_at = datetime.utcnow()
            
            logger.info(
                f"Execution {record_id} "
                f"{'completed' if result.success else 'failed'}"
            )
            
        except Exception as e:
            logger.error(f"Execution {record_id} failed: {e}")
            record.status = ExecutionStatus.FAILED
            record.completed_at = datetime.utcnow()
            record.result = ActionResult(
                action_id=record.action.id,
                success=False,
                message=str(e),
                data={"error": str(e)},
            )
        
        return record
    
    async def process_queue(self, max_concurrent: int = 5) -> List[ExecutionRecord]:
        """
        Process queued executions.
        
        Returns list of processed records.
        """
        processed = []
        
        while self._queue and len(processed) < max_concurrent:
            record_id = self._queue.pop(0)
            
            try:
                record = await self.execute_now(record_id)
                processed.append(record)
            except Exception as e:
                logger.error(f"Failed to process {record_id}: {e}")
        
        return processed
    
    async def approve_and_execute(
        self,
        record_id: str,
        approver: str = "system",
    ) -> ExecutionRecord:
        """
        Approve a pending execution and run it.
        """
        record = self._records.get(record_id)
        if not record:
            raise ValueError(f"Execution record not found: {record_id}")
        
        if record.status != ExecutionStatus.PENDING_APPROVAL:
            raise ValueError(f"Execution not pending approval: {record_id}")
        
        # Approve
        success = await self._approval_gate.approve(
            record.approval_id, approver
        )
        
        if not success:
            raise ValueError(f"Failed to approve: {record.approval_id}")
        
        # Execute
        return await self.execute_now(record_id)
    
    async def cancel(self, record_id: str) -> bool:
        """Cancel a queued or pending execution."""
        record = self._records.get(record_id)
        if not record:
            return False
        
        if record.status in [ExecutionStatus.QUEUED, ExecutionStatus.PENDING_APPROVAL]:
            record.status = ExecutionStatus.CANCELLED
            record.completed_at = datetime.utcnow()
            
            # Remove from queue if present
            if record_id in self._queue:
                self._queue.remove(record_id)
            
            logger.info(f"Execution {record_id} cancelled")
            return True
        
        return False
    
    async def rollback(self, record_id: str) -> ExecutionRecord:
        """Rollback a completed execution."""
        record = self._records.get(record_id)
        if not record:
            raise ValueError(f"Execution record not found: {record_id}")
        
        if record.status != ExecutionStatus.COMPLETED:
            raise ValueError(f"Can only rollback completed executions")
        
        # Create rollback action
        rollback_action = Action.create(
            action_type=ActionType.ROLLBACK,
            description=f"Rollback execution {record_id}",
            parameters={"action_id": record.action.id},
            risk_level="medium",
        )
        
        # Submit rollback
        rollback_record = await self.submit(
            rollback_action,
            org_id=record.org_id,
            initiated_by="system",
            context={"original_execution": record_id},
        )
        
        # Execute immediately (rollbacks should be fast-tracked)
        rollback_record = await self.execute_now(rollback_record.id)
        
        if rollback_record.result and rollback_record.result.success:
            record.status = ExecutionStatus.ROLLED_BACK
        
        return rollback_record
    
    def get_record(self, record_id: str) -> Optional[ExecutionRecord]:
        """Get an execution record."""
        return self._records.get(record_id)
    
    def get_pending_approvals(self) -> List[ExecutionRecord]:
        """Get all executions pending approval."""
        return [
            r for r in self._records.values()
            if r.status == ExecutionStatus.PENDING_APPROVAL
        ]
    
    def get_queue(self) -> List[ExecutionRecord]:
        """Get queued executions."""
        return [
            self._records[rid] for rid in self._queue
            if rid in self._records
        ]
    
    def get_audit_trail(
        self,
        org_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[ExecutionRecord]:
        """Get audit trail of executions."""
        records = list(self._records.values())
        
        if org_id:
            records = [r for r in records if r.org_id == org_id]
        
        # Sort by created_at descending
        records.sort(key=lambda r: r.created_at, reverse=True)
        
        return records[:limit]
