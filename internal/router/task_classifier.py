"""
Advanced Task Classification
=============================

Intelligent task type detection and model selection based on input analysis.
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import re
import logging

logger = logging.getLogger(__name__)


class TaskType(str, Enum):
    """Task types for intelligent routing."""
    REASONING = "reasoning"
    CODE_ANALYSIS = "code_analysis"
    CODE_GENERATION = "code_generation"
    CODE_REVIEW = "code_review"
    SEARCH = "search"
    SUMMARIZATION = "summarization"
    CLASSIFICATION = "classification"
    TRANSLATION = "translation"
    DATA_EXTRACTION = "data_extraction"
    QUESTION_ANSWERING = "question_answering"
    CREATIVE_WRITING = "creative_writing"
    MATH = "math"
    VULNERABILITY_SCAN = "vulnerability_scan"
    THREAT_ANALYSIS = "threat_analysis"
    COMPLIANCE_CHECK = "compliance_check"


class TaskComplexity(str, Enum):
    """Task complexity levels."""
    SIMPLE = "simple"          # <500 tokens, straightforward
    MODERATE = "moderate"      # 500-2000 tokens, some reasoning
    COMPLEX = "complex"        # 2000-8000 tokens, deep analysis
    ADVANCED = "advanced"      # 8000+ tokens, multi-step reasoning


@dataclass
class TaskClassification:
    """Result of task classification."""
    task_type: TaskType
    complexity: TaskComplexity
    confidence: float
    estimated_tokens: int
    requires_context: bool
    recommended_models: List[str]
    reasoning: str
    metadata: Dict[str, Any]


class AdvancedTaskClassifier:
    """
    Advanced task classifier using pattern matching and heuristics.

    In production, this would use ML-based classification.
    """

    def __init__(self):
        """Initialize task classifier."""
        self.task_patterns = self._build_patterns()
        self.code_extensions = {
            '.py', '.js', '.ts', '.java', '.cpp', '.c', '.go', '.rs',
            '.rb', '.php', '.swift', '.kt', '.cs', '.sql', '.sh', '.html',
            '.css', '.jsx', '.tsx', '.vue', '.scala', '.r', '.m'
        }

    def _build_patterns(self) -> Dict[TaskType, List[str]]:
        """Build regex patterns for each task type."""
        return {
            TaskType.CODE_ANALYSIS: [
                r'\banalyze\s+(?:this\s+)?code\b',
                r'\breview\s+(?:this\s+)?code\b',
                r'\bfind\s+bugs?\b',
                r'\bsecurity\s+(?:issues?|vulnerabilities?)\b',
                r'\bcode\s+quality\b',
                r'\bstatic\s+analysis\b',
                r'\blint\b',
            ],
            TaskType.CODE_GENERATION: [
                r'\bwrite\s+(?:a\s+)?(?:function|class|method)\b',
                r'\bgenerate\s+code\b',
                r'\bcreate\s+(?:a\s+)?(?:script|program)\b',
                r'\bimplement\s+',
                r'\bcode\s+(?:a|an)\b',
            ],
            TaskType.CODE_REVIEW: [
                r'\breview\s+(?:this\s+)?(?:PR|pull request|merge request)\b',
                r'\bcode\s+review\b',
                r'\bcheck\s+(?:this\s+)?code\b',
            ],
            TaskType.SEARCH: [
                r'\bsearch\s+for\b',
                r'\bfind\s+(?:information|details|docs?)\b',
                r'\blook\s+up\b',
                r'\bCVE-\d{4}-\d+',
                r'\bwhat\s+is\s+CVE\b',
            ],
            TaskType.SUMMARIZATION: [
                r'\bsummarize\b',
                r'\btl;?dr\b',
                r'\bkey\s+points?\b',
                r'\bmain\s+ideas?\b',
                r'\bbrief\s+(?:overview|summary)\b',
            ],
            TaskType.VULNERABILITY_SCAN: [
                r'\b(?:scan|check)\s+for\s+vulnerabilities\b',
                r'\bsecurity\s+scan\b',
                r'\bpenetration\s+test\b',
                r'\bvulnerability\s+assessment\b',
            ],
            TaskType.THREAT_ANALYSIS: [
                r'\bthreat\s+(?:analysis|modeling|assessment)\b',
                r'\battack\s+(?:vector|surface)\b',
                r'\brisk\s+analysis\b',
            ],
            TaskType.COMPLIANCE_CHECK: [
                r'\bcompliance\s+(?:check|audit)\b',
                r'\b(?:GDPR|HIPAA|SOC2|PCI|DSS)\b',
                r'\bregulatory\s+compliance\b',
            ],
            TaskType.MATH: [
                r'\bcalculate\b',
                r'\bsolve\s+(?:this\s+)?(?:equation|problem)\b',
                r'\bmathematical\b',
                r'\d+\s*[\+\-\*/\^]\s*\d+',
            ],
            TaskType.TRANSLATION: [
                r'\btranslate\b',
                r'\b(?:from|to)\s+(?:English|Spanish|French|German|Chinese|Japanese)\b',
            ],
            TaskType.DATA_EXTRACTION: [
                r'\bextract\s+(?:data|information)\b',
                r'\bparse\s+(?:this|the)\b',
                r'\bget\s+(?:all|the)\s+(?:emails?|names?|dates?|numbers?)\b',
            ],
            TaskType.CREATIVE_WRITING: [
                r'\bwrite\s+(?:a\s+)?(?:story|poem|article|essay)\b',
                r'\bcreative\b',
                r'\bbrainstorm\b',
            ],
            TaskType.QUESTION_ANSWERING: [
                r'\bwhat\s+is\b',
                r'\bhow\s+(?:do|does|can)\b',
                r'\bwhy\s+(?:is|does|do)\b',
                r'\bwhen\s+(?:is|was|did)\b',
                r'\bwhere\s+(?:is|was|can)\b',
            ],
        }

    def classify(
        self,
        input_text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TaskClassification:
        """
        Classify task type and complexity.

        Args:
            input_text: Input text to classify
            context: Optional context for classification

        Returns:
            TaskClassification with type, complexity, and recommendations
        """
        context = context or {}

        # Detect task type
        task_type, confidence = self._detect_task_type(input_text)

        # Estimate complexity
        complexity = self._estimate_complexity(input_text, task_type)

        # Estimate token count
        estimated_tokens = self._estimate_tokens(input_text, task_type)

        # Check if context needed
        requires_context = self._requires_context(input_text, task_type)

        # Recommend models
        recommended_models = self._recommend_models(
            task_type,
            complexity,
            context
        )

        # Generate reasoning
        reasoning = self._generate_reasoning(
            task_type,
            complexity,
            confidence
        )

        # Build metadata
        metadata = {
            "input_length": len(input_text),
            "has_code": self._has_code(input_text),
            "has_urls": self._has_urls(input_text),
            "language_detected": self._detect_language(input_text),
        }

        return TaskClassification(
            task_type=task_type,
            complexity=complexity,
            confidence=confidence,
            estimated_tokens=estimated_tokens,
            requires_context=requires_context,
            recommended_models=recommended_models,
            reasoning=reasoning,
            metadata=metadata
        )

    def _detect_task_type(self, input_text: str) -> Tuple[TaskType, float]:
        """Detect task type using pattern matching."""
        input_lower = input_text.lower()

        # Score each task type
        scores = {}
        for task_type, patterns in self.task_patterns.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, input_lower, re.IGNORECASE):
                    score += 1
            if score > 0:
                scores[task_type] = score

        # Check for code snippets
        if self._has_code(input_text):
            if TaskType.CODE_ANALYSIS in scores:
                scores[TaskType.CODE_ANALYSIS] += 2
            elif TaskType.CODE_GENERATION in scores:
                scores[TaskType.CODE_GENERATION] += 2
            else:
                scores[TaskType.CODE_ANALYSIS] = 1

        # Return highest scoring type, or default to Q&A
        if scores:
            best_type = max(scores.items(), key=lambda x: x[1])
            confidence = min(best_type[1] / 3.0, 1.0)  # Normalize to 0-1
            return best_type[0], confidence
        else:
            return TaskType.QUESTION_ANSWERING, 0.5

    def _estimate_complexity(
        self,
        input_text: str,
        task_type: TaskType
    ) -> TaskComplexity:
        """Estimate task complexity."""
        length = len(input_text)

        # Base complexity on length
        if length < 200:
            base = TaskComplexity.SIMPLE
        elif length < 1000:
            base = TaskComplexity.MODERATE
        elif length < 4000:
            base = TaskComplexity.COMPLEX
        else:
            base = TaskComplexity.ADVANCED

        # Adjust based on task type
        complex_tasks = {
            TaskType.CODE_REVIEW,
            TaskType.VULNERABILITY_SCAN,
            TaskType.THREAT_ANALYSIS,
            TaskType.COMPLIANCE_CHECK,
        }

        if task_type in complex_tasks:
            # Upgrade complexity for inherently complex tasks
            if base == TaskComplexity.SIMPLE:
                return TaskComplexity.MODERATE
            elif base == TaskComplexity.MODERATE:
                return TaskComplexity.COMPLEX

        return base

    def _estimate_tokens(
        self,
        input_text: str,
        task_type: TaskType
    ) -> int:
        """Estimate token count for completion."""
        # Rough estimate: 1 token ≈ 4 characters
        input_tokens = len(input_text) // 4

        # Estimate output tokens based on task type
        output_multipliers = {
            TaskType.SUMMARIZATION: 0.3,
            TaskType.CLASSIFICATION: 0.1,
            TaskType.QUESTION_ANSWERING: 0.5,
            TaskType.CODE_GENERATION: 2.0,
            TaskType.CODE_REVIEW: 1.5,
            TaskType.VULNERABILITY_SCAN: 2.0,
            TaskType.CREATIVE_WRITING: 3.0,
        }

        multiplier = output_multipliers.get(task_type, 1.0)
        estimated_output = int(input_tokens * multiplier)

        # Add base minimum
        total = input_tokens + max(estimated_output, 100)

        return total

    def _requires_context(
        self,
        input_text: str,
        task_type: TaskType
    ) -> bool:
        """Check if task requires conversation context."""
        context_indicators = [
            r'\bthis\s+code\b',
            r'\bthe\s+(?:above|previous|earlier)\b',
            r'\bit\b',
            r'\bthat\b',
            r'\bthese\b',
            r'\bthose\b',
        ]

        for pattern in context_indicators:
            if re.search(pattern, input_text.lower()):
                return True

        # Some task types always benefit from context
        context_tasks = {
            TaskType.CODE_REVIEW,
            TaskType.SUMMARIZATION,
        }

        return task_type in context_tasks

    def _recommend_models(
        self,
        task_type: TaskType,
        complexity: TaskComplexity,
        context: Dict[str, Any]
    ) -> List[str]:
        """Recommend models for task."""
        # Model preferences by task type
        preferences = {
            TaskType.CODE_ANALYSIS: ["deepseek-coder-33b", "gpt-4o", "claude-3-opus"],
            TaskType.CODE_GENERATION: ["deepseek-coder-33b", "gpt-4o", "claude-3-sonnet"],
            TaskType.CODE_REVIEW: ["gpt-4o", "claude-3-opus", "deepseek-coder-33b"],
            TaskType.VULNERABILITY_SCAN: ["gpt-4o", "claude-3-opus", "llama3.2"],
            TaskType.THREAT_ANALYSIS: ["gpt-4o", "claude-3-opus"],
            TaskType.COMPLIANCE_CHECK: ["gpt-4o", "claude-3-sonnet"],
            TaskType.MATH: ["gpt-4o", "claude-3-opus", "llama3.2"],
            TaskType.CREATIVE_WRITING: ["claude-3-opus", "gpt-4o", "mixtral-8x7b"],
            TaskType.SUMMARIZATION: ["gpt-3.5-turbo", "mixtral-8x7b", "llama3.2"],
            TaskType.QUESTION_ANSWERING: ["gpt-3.5-turbo", "mixtral-8x7b", "llama3.2"],
        }

        models = preferences.get(task_type, ["gpt-3.5-turbo", "llama3.2"])

        # Adjust for complexity
        if complexity in [TaskComplexity.COMPLEX, TaskComplexity.ADVANCED]:
            # Prefer more capable models
            if "gpt-3.5-turbo" in models:
                models = ["gpt-4o"] + [m for m in models if m != "gpt-3.5-turbo"]

        # Check privacy requirements from context
        if context.get("requires_local", False):
            # Filter to local-only models
            local_models = ["llama3.2", "mixtral-8x7b", "deepseek-coder-33b"]
            models = [m for m in models if m in local_models]
            if not models:
                models = ["llama3.2"]

        return models[:3]  # Return top 3

    def _generate_reasoning(
        self,
        task_type: TaskType,
        complexity: TaskComplexity,
        confidence: float
    ) -> str:
        """Generate reasoning for classification."""
        return (
            f"Classified as {task_type.value} "
            f"(confidence: {confidence:.2f}) "
            f"with {complexity.value} complexity"
        )

    def _has_code(self, text: str) -> bool:
        """Check if text contains code snippets."""
        code_indicators = [
            r'```',  # Code blocks
            r'function\s+\w+\s*\(',
            r'class\s+\w+',
            r'def\s+\w+\s*\(',
            r'import\s+\w+',
            r'from\s+\w+\s+import',
            r'SELECT\s+.*FROM',
            r'#include\s*<',
            r'\bconst\s+\w+\s*=',
            r'\blet\s+\w+\s*=',
            r'\bvar\s+\w+\s*=',
        ]

        for pattern in code_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False

    def _has_urls(self, text: str) -> bool:
        """Check if text contains URLs."""
        url_pattern = r'https?://[^\s]+'
        return bool(re.search(url_pattern, text))

    def _detect_language(self, text: str) -> str:
        """Detect programming language (simple heuristic)."""
        if not self._has_code(text):
            return "natural"

        # Simple keyword-based detection
        if re.search(r'\bdef\s+\w+\s*\(', text):
            return "python"
        elif re.search(r'\bfunction\s+\w+\s*\(', text):
            return "javascript"
        elif re.search(r'\bclass\s+\w+\s*{', text):
            return "java"
        elif re.search(r'SELECT\s+.*FROM', text, re.IGNORECASE):
            return "sql"
        else:
            return "unknown"


# Global classifier instance
task_classifier = AdvancedTaskClassifier()
