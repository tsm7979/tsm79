"""
Fix Playbook Engine

Replace LLM calls over time with proven fix strategies.
Playbooks accumulate knowledge about what works.

Instead of: "Ask Claude how to fix X"
We do: "Check if we've fixed X successfully before"

The playbook system provides:
- Known fix patterns with confidence scores
- Context-aware matching
- Automatic confidence updates from outcomes
- LLM fallback when confidence is low
"""

from __future__ import annotations

import uuid
import json
import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ApprovalPolicy(str, Enum):
    """Playbook approval policies."""
    
    AUTO_APPLY = "auto_apply"
    HUMAN_REVIEW = "human_review"
    TEAM_APPROVAL = "team_approval"


@dataclass
class SuccessMetrics:
    """Tracks success/failure counts for a playbook."""
    
    successful_fixes: int = 0
    failed_fixes: int = 0
    regressions: int = 0
    total_uses: int = 0
    last_used: Optional[datetime] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_uses == 0:
            return 0.0
        return self.successful_fixes / self.total_uses
    
    def record_success(self) -> None:
        """Record a successful fix."""
        self.successful_fixes += 1
        self.total_uses += 1
        self.last_used = datetime.now()
    
    def record_failure(self, is_regression: bool = False) -> None:
        """Record a failed fix."""
        self.failed_fixes += 1
        self.total_uses += 1
        if is_regression:
            self.regressions += 1
        self.last_used = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "successful_fixes": self.successful_fixes,
            "failed_fixes": self.failed_fixes,
            "regressions": self.regressions,
            "total_uses": self.total_uses,
            "success_rate": self.success_rate,
            "last_used": self.last_used.isoformat() if self.last_used else None,
        }


@dataclass
class FixStrategy:
    """
    Defines how to fix a specific issue.
    
    Attributes:
        description: Human-readable description
        code_pattern: Pattern identifier for code generation
        fix_template: Template for the fix
        test_requirements: Required tests after fix
        rollback_steps: How to rollback if needed
    """
    
    description: str = ""
    code_pattern: str = ""
    fix_template: Optional[str] = None
    test_requirements: List[str] = field(default_factory=list)
    rollback_steps: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "code_pattern": self.code_pattern,
            "fix_template": self.fix_template,
            "test_requirements": self.test_requirements,
            "rollback_steps": self.rollback_steps,
        }


@dataclass
class ContextConstraints:
    """
    Context constraints for playbook matching.
    
    Ensures playbook is only used in appropriate contexts.
    """
    
    languages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    orms: List[str] = field(default_factory=list)
    databases: List[str] = field(default_factory=list)
    environments: List[str] = field(default_factory=list)
    
    def matches(self, context: Dict[str, Any]) -> bool:
        """Check if context matches constraints."""
        # Empty constraint means match all
        if self.languages and context.get("language") not in self.languages:
            return False
        if self.frameworks and context.get("framework") not in self.frameworks:
            return False
        if self.orms and context.get("orm") not in self.orms:
            return False
        if self.databases and context.get("database") not in self.databases:
            return False
        if self.environments and context.get("environment") not in self.environments:
            return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "languages": self.languages,
            "frameworks": self.frameworks,
            "orms": self.orms,
            "databases": self.databases,
            "environments": self.environments,
        }


@dataclass
class FixPlaybook:
    """
    A playbook for fixing a specific type of issue.
    
    Playbooks replace LLM calls with proven fix strategies.
    They accumulate knowledge and confidence over time.
    
    Attributes:
        playbook_id: Unique identifier
        finding_type: Type of finding this fixes
        language: Programming language
        framework: Framework if applicable
        context_constraints: When to apply this playbook
        fix_strategy: How to fix the issue
        confidence: Current confidence (0-1)
        success_metrics: Success/failure tracking
        approval_policy: How fixes are approved
        created_at: When playbook was created
        source: How playbook was created
    """
    
    playbook_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_type: str = ""
    language: str = ""
    framework: str = ""
    context_constraints: ContextConstraints = field(default_factory=ContextConstraints)
    fix_strategy: FixStrategy = field(default_factory=FixStrategy)
    confidence: float = 0.5
    success_metrics: SuccessMetrics = field(default_factory=SuccessMetrics)
    approval_policy: ApprovalPolicy = ApprovalPolicy.HUMAN_REVIEW
    auto_apply_threshold: float = 0.90
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    source: str = "manual"  # manual, learned, llm_converted
    
    @property
    def key(self) -> str:
        """Generate a unique key for matching."""
        return f"{self.finding_type}|{self.language}|{self.framework}"
    
    @property
    def can_auto_apply(self) -> bool:
        """Check if this playbook can be auto-applied."""
        return (
            self.approval_policy == ApprovalPolicy.AUTO_APPLY and
            self.confidence >= self.auto_apply_threshold
        )
    
    def matches_context(self, context: Dict[str, Any]) -> bool:
        """Check if this playbook matches the given context."""
        return self.context_constraints.matches(context)
    
    def update_from_outcome(self, success: bool, regression: bool = False) -> None:
        """Update playbook based on an outcome."""
        if success:
            self.success_metrics.record_success()
        else:
            self.success_metrics.record_failure(regression)
        
        self.updated_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "finding_type": self.finding_type,
            "language": self.language,
            "framework": self.framework,
            "context_constraints": self.context_constraints.to_dict(),
            "fix_strategy": self.fix_strategy.to_dict(),
            "confidence": self.confidence,
            "success_metrics": self.success_metrics.to_dict(),
            "approval_policy": self.approval_policy.value,
            "auto_apply_threshold": self.auto_apply_threshold,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "source": self.source,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FixPlaybook":
        """Create playbook from dictionary."""
        constraints = ContextConstraints(**data.get("context_constraints", {}))
        strategy = FixStrategy(**data.get("fix_strategy", {}))
        
        # Clean metrics data
        metrics_data = data.get("success_metrics", {}).copy()
        metrics_data.pop("success_rate", None)  # Remove computed property
        
        # Parse last_used if string
        if metrics_data.get("last_used") and isinstance(metrics_data["last_used"], str):
             try:
                 metrics_data["last_used"] = datetime.fromisoformat(metrics_data["last_used"])
             except ValueError:
                 metrics_data["last_used"] = None
                 
        metrics = SuccessMetrics(**metrics_data)
        
        # Parse timestamps for Playbook
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at)
        else:
            created_at = datetime.now()

        updated_at = data.get("updated_at")
        if isinstance(updated_at, str):
            updated_at = datetime.fromisoformat(updated_at)
        else:
            updated_at = datetime.now()
        
        return cls(
            playbook_id=data.get("playbook_id", str(uuid.uuid4())),
            finding_type=data.get("finding_type", ""),
            language=data.get("language", ""),
            framework=data.get("framework", ""),
            context_constraints=constraints,
            fix_strategy=strategy,
            confidence=data.get("confidence", 0.5),
            success_metrics=metrics,
            approval_policy=ApprovalPolicy(data.get("approval_policy", "human_review")),
            auto_apply_threshold=data.get("auto_apply_threshold", 0.90),
            created_at=created_at,
            updated_at=updated_at,
            source=data.get("source", "unknown"),
        )



@dataclass
class PlaybookMatch:
    """Result of matching a finding to a playbook."""
    
    playbook: FixPlaybook
    match_score: float
    match_reason: str
    use_playbook: bool
    fallback_to_llm: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook.playbook_id,
            "confidence": self.playbook.confidence,
            "match_score": self.match_score,
            "match_reason": self.match_reason,
            "use_playbook": self.use_playbook,
            "fallback_to_llm": self.fallback_to_llm,
        }


class PlaybookEngine(BaseModel):
    """
    Fix Playbook Engine - LLM Replacement System.
    
    Manages playbooks for fixing security issues.
    Over time, reduces LLM dependency by using proven strategies.
    
    Flow:
    1. New finding arrives
    2. Check for matching playbook
    3. If confidence HIGH -> Apply playbook directly
    4. If confidence LOW -> Fall back to LLM
    5. After verification -> Update playbook confidence
    
    Attributes:
        name: Engine identifier
        storage_path: Path for playbook storage
        min_confidence_for_auto: Minimum confidence for auto-apply
        min_confidence_for_suggestion: Minimum to suggest playbook
        on_playbook_selected: Callback when playbook is used
        on_llm_fallback: Callback when falling back to LLM
    """
    
    model_config = {"arbitrary_types_allowed": True}
    
    name: str = Field(default="playbook_engine")
    storage_path: Optional[str] = Field(default=None)
    min_confidence_for_auto: float = Field(default=0.90)
    min_confidence_for_suggestion: float = Field(default=0.70)
    
    on_playbook_selected: Optional[Callable[[FixPlaybook], None]] = Field(default=None)
    on_llm_fallback: Optional[Callable[[str, str], None]] = Field(default=None)
    
    _playbooks: Dict[str, FixPlaybook] = {}
    _by_finding_type: Dict[str, List[str]] = {}
    _pattern_store: Any = None # PatternStore injection

    def __init__(self, **data: Any):
        super().__init__(**data)
        self._playbooks = {}
        self._by_finding_type = {}
        
        # Lazy load store
        from learning.pattern_store import PatternStore
        self._pattern_store = PatternStore(self.storage_path)

        if self.storage_path:
            self._load()
        
        # Initialize with built-in playbooks
        self._load_builtin_playbooks()
    
    def add_playbook(self, playbook: FixPlaybook) -> None:
        """Add a playbook to the engine."""
        self._playbooks[playbook.playbook_id] = playbook
        
        if playbook.finding_type not in self._by_finding_type:
            self._by_finding_type[playbook.finding_type] = []
        self._by_finding_type[playbook.finding_type].append(playbook.playbook_id)
        
        if self.storage_path:
            self._persist(playbook)
        
        logger.info(f"Playbook added: {playbook.playbook_id} for {playbook.finding_type}")
    
    def get_playbook(self, playbook_id: str) -> Optional[FixPlaybook]:
        """Get a playbook by ID."""
        return self._playbooks.get(playbook_id)
    
    def find_matching_playbook(
        self,
        finding_type: str,
        context: Dict[str, Any],
    ) -> Optional[PlaybookMatch]:
        """
        Find the best matching playbook for a finding.
        
        Args:
            finding_type: Type of finding
            context: Execution context (language, framework, etc.)
            
        Returns:
            PlaybookMatch or None if no match
        """
        candidates = self._by_finding_type.get(finding_type, [])
        
        if not candidates:
            logger.debug(f"No playbooks for finding type: {finding_type}")
            return None
        
        best_match = None
        best_score = 0.0
        
        for playbook_id in candidates:
            playbook = self._playbooks.get(playbook_id)
            if not playbook:
                continue
            
            # Check context match
            if not playbook.matches_context(context):
                continue
            
            # Calculate match score (confidence + context specificity)
            score = playbook.confidence
            
            # Bonus for specific language/framework match
            if context.get("language") == playbook.language:
                score += 0.1
            if context.get("framework") == playbook.framework:
                score += 0.1
            
            if score > best_score:
                best_score = score
                best_match = playbook
        
        if not best_match:
            return None
        
        # Decide whether to use playbook or LLM
        use_playbook = best_match.confidence >= self.min_confidence_for_suggestion
        fallback_to_llm = best_match.confidence < self.min_confidence_for_auto
        
        if use_playbook and self.on_playbook_selected:
            self.on_playbook_selected(best_match)
        elif fallback_to_llm and self.on_llm_fallback:
            self.on_llm_fallback(finding_type, "confidence_too_low")
        
        return PlaybookMatch(
            playbook=best_match,
            match_score=best_score,
            match_reason="context_and_confidence_match",
            use_playbook=use_playbook,
            fallback_to_llm=fallback_to_llm,
        )
    
    def get_fix_decision(
        self,
        finding_type: str,
        context: Dict[str, Any],
    ) -> Tuple[str, Optional[FixPlaybook], str]:
        """
        Get the decision on how to fix a finding.
        CHECK NEGATIVE LEARNING FIRST.
        """
        # Hard check for negative learning
        if self._pattern_store: # Need to inject this
             # For playbooks, we check the code_pattern as a snippet proxy
            match = self.find_matching_playbook(finding_type, context)
            if match and match.playbook.fix_strategy.code_pattern:
                if self._pattern_store.is_abandoned(match.playbook.fix_strategy.code_pattern, finding_type):
                     return ("use_llm", None, "suppressed_by_negative_learning")

        match = self.find_matching_playbook(finding_type, context)
        
        if not match:
             return ("use_llm", None, "no_matching_playbook")
        
        if match.use_playbook and not match.fallback_to_llm:
             return ("use_playbook", match.playbook, f"confidence={match.playbook.confidence:.2f}")
        elif match.use_playbook and match.fallback_to_llm:
             return ("use_playbook_with_review", match.playbook, "confidence_marginal")
        else:
             return ("use_llm", None, "confidence_too_low")
    
    def create_playbook_from_llm_fix(
        self,
        finding_type: str,
        language: str,
        framework: str,
        fix_description: str,
        fix_template: str,
        initial_confidence: float = 0.5,
    ) -> FixPlaybook:
        """
        Create a new playbook from a successful LLM fix.
        
        This is how the system learns from LLM outputs.
        Over time, these playbooks replace LLM calls.
        """
        playbook = FixPlaybook(
            finding_type=finding_type,
            language=language,
            framework=framework,
            fix_strategy=FixStrategy(
                description=fix_description,
                code_pattern="llm_derived",
                fix_template=fix_template,
            ),
            confidence=initial_confidence,
            source="llm_converted",
        )
        
        self.add_playbook(playbook)
        
        logger.info(f"Created playbook from LLM fix: {playbook.playbook_id}")
        
        return playbook
    
    def update_confidence(
        self,
        playbook_id: str,
        new_confidence: float,
    ) -> None:
        """Update a playbook's confidence."""
        playbook = self._playbooks.get(playbook_id)
        if playbook:
            playbook.confidence = max(0.0, min(1.0, new_confidence))
            playbook.updated_at = datetime.now()
            
            if self.storage_path:
                self._persist(playbook)
    
    def get_playbooks_for_type(self, finding_type: str) -> List[FixPlaybook]:
        """Get all playbooks for a finding type."""
        ids = self._by_finding_type.get(finding_type, [])
        return [self._playbooks[id] for id in ids if id in self._playbooks]
    
    def get_all_playbooks(self) -> List[FixPlaybook]:
        """Get all playbooks."""
        return list(self._playbooks.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get playbook engine statistics."""
        playbooks = list(self._playbooks.values())
        
        high_confidence = [p for p in playbooks if p.confidence >= 0.9]
        medium_confidence = [p for p in playbooks if 0.7 <= p.confidence < 0.9]
        low_confidence = [p for p in playbooks if p.confidence < 0.7]
        
        return {
            "total_playbooks": len(playbooks),
            "high_confidence": len(high_confidence),
            "medium_confidence": len(medium_confidence),
            "low_confidence": len(low_confidence),
            "finding_types_covered": len(self._by_finding_type),
            "sources": {
                "manual": len([p for p in playbooks if p.source == "manual"]),
                "llm_converted": len([p for p in playbooks if p.source == "llm_converted"]),
                "learned": len([p for p in playbooks if p.source == "learned"]),
            },
        }
    
    def _load_builtin_playbooks(self) -> None:
        """Load built-in security fix playbooks."""
        builtin = [
            FixPlaybook(
                playbook_id="PB-SQLI-NODE-EXPRESS-001",
                finding_type="SQL_INJECTION",
                language="nodejs",
                framework="express",
                context_constraints=ContextConstraints(
                    languages=["nodejs", "javascript", "typescript"],
                    frameworks=["express", "fastify", "koa"],
                    orms=["sequelize", "typeorm", "knex", "prisma"],
                ),
                fix_strategy=FixStrategy(
                    description="Replace string interpolation with parameterized queries",
                    code_pattern="parameterized_query",
                    test_requirements=["unit_test_added", "input_validation_test"],
                ),
                confidence=0.94,
                approval_policy=ApprovalPolicy.AUTO_APPLY,
                source="builtin",
            ),
            FixPlaybook(
                playbook_id="PB-XSS-REACT-001",
                finding_type="XSS",
                language="javascript",
                framework="react",
                context_constraints=ContextConstraints(
                    languages=["javascript", "typescript"],
                    frameworks=["react", "nextjs"],
                ),
                fix_strategy=FixStrategy(
                    description="Replace dangerouslySetInnerHTML with sanitized content",
                    code_pattern="sanitize_html",
                    test_requirements=["xss_test", "render_test"],
                ),
                confidence=0.91,
                approval_policy=ApprovalPolicy.AUTO_APPLY,
                source="builtin",
            ),
            FixPlaybook(
                playbook_id="PB-HARDCODED-SECRET-001",
                finding_type="HARDCODED_SECRET",
                language="any",
                framework="any",
                fix_strategy=FixStrategy(
                    description="Move secret to environment variable or secret manager",
                    code_pattern="env_variable",
                    test_requirements=["secret_scan", "env_exists"],
                ),
                confidence=0.95,
                approval_policy=ApprovalPolicy.HUMAN_REVIEW,
                source="builtin",
            ),
            FixPlaybook(
                playbook_id="PB-INSECURE-DESERIALIZATION-001",
                finding_type="INSECURE_DESERIALIZATION",
                language="python",
                framework="any",
                context_constraints=ContextConstraints(
                    languages=["python"],
                ),
                fix_strategy=FixStrategy(
                    description="Replace pickle with JSON or use safe_load for YAML",
                    code_pattern="safe_serialization",
                    test_requirements=["deserialization_test"],
                ),
                confidence=0.88,
                approval_policy=ApprovalPolicy.HUMAN_REVIEW,
                source="builtin",
            ),
            FixPlaybook(
                playbook_id="PB-CMD-INJECTION-001",
                finding_type="COMMAND_INJECTION",
                language="any",
                framework="any",
                fix_strategy=FixStrategy(
                    description="Use subprocess with shell=False and explicit args list",
                    code_pattern="safe_subprocess",
                    test_requirements=["command_test", "input_validation"],
                ),
                confidence=0.92,
                approval_policy=ApprovalPolicy.HUMAN_REVIEW,
                source="builtin",
            ),
        ]
        
        for playbook in builtin:
            if playbook.playbook_id not in self._playbooks:
                self.add_playbook(playbook)
    
    def _persist(self, playbook: FixPlaybook) -> None:
        """Persist a playbook to disk."""
        if not self.storage_path:
            return
        
        path = Path(self.storage_path)
        path.mkdir(parents=True, exist_ok=True)
        
        file_path = path / f"{playbook.playbook_id}.json"
        with open(file_path, "w") as f:
            f.write(playbook.to_json())
    
    def _load(self) -> None:
        """Load playbooks from disk."""
        if not self.storage_path:
            return
        
        path = Path(self.storage_path)
        if not path.exists():
            return
        
        for file_path in path.glob("*.json"):
            try:
                with open(file_path) as f:
                    data = json.load(f)
                    playbook = FixPlaybook.from_dict(data)
                    self._playbooks[playbook.playbook_id] = playbook
                    
                    if playbook.finding_type not in self._by_finding_type:
                        self._by_finding_type[playbook.finding_type] = []
                    self._by_finding_type[playbook.finding_type].append(playbook.playbook_id)
            except Exception as e:
                logger.error(f"Failed to load playbook {file_path}: {e}")
        
        logger.info(f"Loaded {len(self._playbooks)} playbooks from storage")
