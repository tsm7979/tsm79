"""
Risk Classification Engine
==========================

Classifies input risk tier to drive routing decisions.
"""

from enum import Enum
from typing import Dict, Any, List
from dataclasses import dataclass
import logging

from firewall.sanitizer import SensitivityLevel

logger = logging.getLogger(__name__)


class RiskTier(str, Enum):
    """Risk classification tiers"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InputCategory(str, Enum):
    """Input content categories"""
    GENERAL = "general"
    TECHNICAL = "technical"
    SECURITY = "security"
    FINANCIAL = "financial"
    PERSONAL = "personal"
    ENTERPRISE = "enterprise"


@dataclass
class RiskClassification:
    """Result of risk classification"""
    tier: RiskTier
    category: InputCategory
    sensitivity: SensitivityLevel
    factors: List[str]
    confidence: float
    requires_local_only: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier.value,
            "category": self.category.value,
            "sensitivity": self.sensitivity.value,
            "factors": self.factors,
            "confidence": self.confidence,
            "requires_local_only": self.requires_local_only
        }


class RiskClassifier:
    """
    Classifies input risk based on multiple factors.

    Used by router to decide:
    - Local vs cloud model
    - Which model tier to use
    - Whether to require simulation
    - Whether to require approval
    """

    def __init__(self):
        self.pii_keywords = [
            "ssn", "social security", "credit card", "password",
            "secret", "token", "api key", "private key"
        ]
        self.technical_keywords = [
            "code", "function", "class", "method", "database",
            "query", "vulnerability", "exploit", "security"
        ]
        self.financial_keywords = [
            "account", "balance", "transaction", "payment",
            "invoice", "revenue", "profit"
        ]

    async def classify(
        self,
        input_text: str,
        context: Dict[str, Any],
        sanitization_result: Any = None
    ) -> RiskClassification:
        """
        Classify input risk tier.

        Args:
            input_text: Sanitized input text
            context: User/org context
            sanitization_result: Result from sanitizer (if available)

        Returns:
            RiskClassification with tier and factors
        """
        factors = []
        tier = RiskTier.LOW
        category = InputCategory.GENERAL
        requires_local = False

        # Factor 1: Sanitization results
        if sanitization_result:
            sensitivity = sanitization_result.sensitivity_detected
            redaction_count = len(sanitization_result.redactions)

            if sensitivity == SensitivityLevel.RESTRICTED:
                tier = RiskTier.CRITICAL
                requires_local = True
                factors.append(f"Restricted data detected ({redaction_count} redactions)")
            elif sensitivity == SensitivityLevel.CONFIDENTIAL:
                tier = max(tier, RiskTier.HIGH)
                requires_local = True
                factors.append(f"Confidential data detected ({redaction_count} redactions)")
            elif sensitivity == SensitivityLevel.INTERNAL:
                tier = max(tier, RiskTier.MEDIUM)
                factors.append("Internal data detected")
        else:
            sensitivity = SensitivityLevel.PUBLIC

        # Factor 2: Content keywords
        input_lower = input_text.lower()

        pii_detected = any(kw in input_lower for kw in self.pii_keywords)
        if pii_detected:
            tier = max(tier, RiskTier.HIGH)
            requires_local = True
            factors.append("PII keywords detected")
            category = InputCategory.PERSONAL

        tech_detected = any(kw in input_lower for kw in self.technical_keywords)
        if tech_detected:
            tier = max(tier, RiskTier.MEDIUM)
            factors.append("Technical content detected")
            if category == InputCategory.GENERAL:
                category = InputCategory.TECHNICAL

        financial_detected = any(kw in input_lower for kw in self.financial_keywords)
        if financial_detected:
            tier = max(tier, RiskTier.HIGH)
            factors.append("Financial content detected")
            category = InputCategory.FINANCIAL

        # Factor 3: Input length (very long = potential data dump)
        if len(input_text) > 10000:
            tier = max(tier, RiskTier.MEDIUM)
            factors.append("Large input detected")

        # Factor 4: Org context (if enterprise, higher baseline)
        if context.get("org_type") == "enterprise":
            if tier == RiskTier.LOW:
                tier = RiskTier.MEDIUM
            factors.append("Enterprise context")
            category = InputCategory.ENTERPRISE

        # Factor 5: Special security context
        if context.get("security_context"):
            tier = max(tier, RiskTier.MEDIUM)
            factors.append("Security context")
            category = InputCategory.SECURITY

        # Calculate confidence
        confidence = 0.7 + (len(factors) * 0.05)
        confidence = min(confidence, 0.95)

        logger.info(
            f"Risk classification: tier={tier.value}, "
            f"category={category.value}, factors={len(factors)}"
        )

        return RiskClassification(
            tier=tier,
            category=category,
            sensitivity=sensitivity,
            factors=factors,
            confidence=confidence,
            requires_local_only=requires_local
        )

    def should_require_approval(self, classification: RiskClassification) -> bool:
        """Check if request requires human approval"""
        return classification.tier == RiskTier.CRITICAL

    def should_simulate(self, classification: RiskClassification) -> bool:
        """Check if request should be simulated first"""
        return classification.tier in [RiskTier.HIGH, RiskTier.CRITICAL]
