import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class PatternStats(BaseModel):
    """
    Tracks the performance and confidence of a specific fix pattern.
    """
    pattern_id: str
    signature: str 
    
    times_suggested: int = 0
    times_applied: int = 0
    success_count: int = 0
    failure_count: int = 0
    
    confidence: float = 0.0 
    last_success_at: Optional[datetime] = None
    last_failure_at: Optional[datetime] = None
    
    status: str = "candidate" 

    def update_outcome(self, success: bool):
        self.times_applied += 1
        
        if success:
            self.success_count += 1
            # Reward: +0.1
            self.confidence = min(1.0, self.confidence + 0.1)
            self.last_success_at = datetime.now()
        else:
            self.failure_count += 1
            # Penalty: -0.2 
            self.confidence = max(0.0, self.confidence - 0.2)
            self.last_failure_at = datetime.now()

        self._update_status()

    def _update_status(self):
        if self.confidence <= 0.2 and self.times_applied > 5:
            self.status = "disabled"
        elif self.confidence <= 0.4:
            self.status = "decaying"
        elif self.confidence >= 0.8:
            self.status = "trusted"
        else:
            self.status = "candidate"

class AbandonedAttempt(BaseModel):
    """
    Tracks abandoned attempts to prevent re-suggesting failed fixes.
    NEGATIVE DATA - Teaches system what NOT to do.
    """
    language: str
    snippet: str # Hash or snippets
    reason: str
    finding_type: str
    attempted_at: datetime = Field(default_factory=datetime.now)

class PatternStore:
    """
    Persistent store for patterns.
    """
    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = Path(storage_path) if storage_path else None
        self.patterns: Dict[str, PatternStats] = {}
        self.abandoned: List[AbandonedAttempt] = [] # List of abandoned attempts
        if self.storage_path:
            self._load()

    def get_pattern(self, pattern_id: str) -> Optional[PatternStats]:
        return self.patterns.get(pattern_id)

    def create_pattern(self, pattern_id: str, signature: str) -> PatternStats:
        pattern = PatternStats(pattern_id=pattern_id, signature=signature)
        self.patterns[pattern_id] = pattern
        self._persist() # Save on creation
        return pattern
    
    def register_outcome(self, pattern_id: str, success: bool):
        pattern = self.patterns.get(pattern_id)
        if pattern:
            pattern.update_outcome(success)
            self._persist() # Save on update

    def register_abandoned(self, language: str, snippet: str, reason: str, finding_type: str):
        attempt = AbandonedAttempt(
            language=language,
            snippet=snippet,
            reason=reason,
            finding_type=finding_type
        )
        self.abandoned.append(attempt)
        self._persist_abandoned()

    def is_abandoned(self, snippet: str, finding_type: str) -> bool:
        """Check if a snippet/strategy has been abandoned for this finding type."""
        # Simple exact match for MVP. In prod, use semantic hash.
        for attempt in self.abandoned:
            if attempt.snippet == snippet and attempt.finding_type == finding_type:
                return True
        return False

    def _persist(self):
        if not self.storage_path:
            return
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        file_path = self.storage_path / "patterns.jsonl"
        
        try:
            with open(file_path, "w") as f:
                for p in self.patterns.values():
                    f.write(p.model_dump_json() + "\n")
        except Exception as e:
            logger.error(f"Failed to persist patterns: {e}")

    def _persist_abandoned(self):
        if not self.storage_path:
            return
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        file_path = self.storage_path / "abandoned.jsonl"
        
        try:
             with open(file_path, "w") as f:
                for a in self.abandoned:
                    f.write(a.model_dump_json() + "\n")
        except Exception as e:
            logger.error(f"Failed to persist abandoned: {e}")

    def _load(self):
        if not self.storage_path:
            return
            
        # Load Patterns
        file_path = self.storage_path / "patterns.jsonl"
        if file_path.exists():
            try:
                with open(file_path, "r") as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            pattern = PatternStats(**data)
                            self.patterns[pattern.pattern_id] = pattern
                logger.info(f"Loaded {len(self.patterns)} patterns")
            except Exception as e:
                logger.error(f"Failed to load patterns: {e}")

        # Load Abandoned
        abandoned_path = self.storage_path / "abandoned.jsonl"
        if abandoned_path.exists():
            try:
                 with open(abandoned_path, "r") as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            attempt = AbandonedAttempt(**data)
                            self.abandoned.append(attempt)
                 logger.info(f"Loaded {len(self.abandoned)} abandoned attempts")
            except Exception as e:
                logger.error(f"Failed to load abandoned: {e}")
