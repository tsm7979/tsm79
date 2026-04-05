"""
TSM Layer Firewall
==================

Privacy and sanitization layer. All inputs pass through here.

Key functions:
- PII detection and removal
- Secret detection and redaction
- Risk classification
- Context-aware sanitization
"""

from firewall.sanitizer import (
    DataSanitizer,
    SanitizationResult,
    SensitivityLevel,
    sanitize_for_llm
)
from firewall.classifier import RiskClassifier, RiskTier

__all__ = [
    "DataSanitizer",
    "SanitizationResult",
    "SensitivityLevel",
    "sanitize_for_llm",
    "RiskClassifier",
    "RiskTier"
]

# Default instances
sanitizer = DataSanitizer()
classifier = RiskClassifier()
