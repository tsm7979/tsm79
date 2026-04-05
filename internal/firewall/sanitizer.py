"""
Data Sanitization Module

Ensures all data sent to external LLMs is sanitized, containing only:
- Abstracted context
- Hashed references
- Metadata
- Diffs (sanitized)
- Policies

NEVER sends:
- Raw logs
- Secrets
- Source code (unless explicitly approved)
- PII
- Credentials

This is the core of the data-resident architecture.
"""

from __future__ import annotations

import re
import uuid
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set, Callable, Pattern
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SensitivityLevel(str, Enum):
    """Data sensitivity classification."""
    
    PUBLIC = "public"           # Safe to send externally
    INTERNAL = "internal"       # Hash before sending
    CONFIDENTIAL = "confidential"  # Never send, reference only
    RESTRICTED = "restricted"   # Requires explicit approval


class DataType(str, Enum):
    """Types of data that may need sanitization."""
    
    LOG = "log"
    CODE = "code"
    CONFIG = "config"
    SECRET = "secret"
    PII = "pii"
    CREDENTIALS = "credentials"
    METADATA = "metadata"
    DIFF = "diff"
    PATH = "path"
    QUERY = "query"


@dataclass
class SanitizationRule:
    """A rule for detecting and sanitizing sensitive data."""
    
    name: str
    pattern: Pattern
    data_type: DataType
    sensitivity: SensitivityLevel
    replacement: str = "[REDACTED]"
    hash_instead: bool = False
    
    def apply(self, text: str) -> str:
        """Apply this sanitization rule to text."""
        if self.hash_instead:
            def hash_match(match):
                return f"[REF:{hashlib.sha256(match.group().encode()).hexdigest()[:12]}]"
            return self.pattern.sub(hash_match, text)
        return self.pattern.sub(self.replacement, text)


# Pre-defined sanitization patterns
DEFAULT_SANITIZATION_RULES = [
    # Secrets and credentials
    SanitizationRule(
        name="api_keys",
        pattern=re.compile(r'(?:api[_-]?key|apikey)["\s:=]+["\']?[\w\-]{20,}["\']?', re.IGNORECASE),
        data_type=DataType.SECRET,
        sensitivity=SensitivityLevel.RESTRICTED,
        replacement="[API_KEY_REDACTED]"
    ),
    SanitizationRule(
        name="passwords",
        pattern=re.compile(r'(?:password|passwd|pwd)["\s:=]+["\']?[^\s"\']{8,}["\']?', re.IGNORECASE),
        data_type=DataType.CREDENTIALS,
        sensitivity=SensitivityLevel.RESTRICTED,
        replacement="[PASSWORD_REDACTED]"
    ),
    SanitizationRule(
        name="tokens",
        pattern=re.compile(r'(?:token|bearer|auth)["\s:=]+["\']?[\w\-\.]{20,}["\']?', re.IGNORECASE),
        data_type=DataType.SECRET,
        sensitivity=SensitivityLevel.RESTRICTED,
        replacement="[TOKEN_REDACTED]"
    ),
    SanitizationRule(
        name="private_keys",
        pattern=re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----'),
        data_type=DataType.SECRET,
        sensitivity=SensitivityLevel.RESTRICTED,
        replacement="[PRIVATE_KEY_REDACTED]"
    ),
    SanitizationRule(
        name="aws_keys",
        pattern=re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'),
        data_type=DataType.CREDENTIALS,
        sensitivity=SensitivityLevel.RESTRICTED,
        replacement="[AWS_KEY_REDACTED]"
    ),
    
    # PII
    SanitizationRule(
        name="emails",
        pattern=re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        data_type=DataType.PII,
        sensitivity=SensitivityLevel.CONFIDENTIAL,
        hash_instead=True
    ),
    SanitizationRule(
        name="phones",
        pattern=re.compile(r'(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'),
        data_type=DataType.PII,
        sensitivity=SensitivityLevel.CONFIDENTIAL,
        replacement="[PHONE_REDACTED]"
    ),
    SanitizationRule(
        name="ssn",
        pattern=re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        data_type=DataType.PII,
        sensitivity=SensitivityLevel.RESTRICTED,
        replacement="[SSN_REDACTED]"
    ),
    SanitizationRule(
        name="credit_cards",
        pattern=re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        data_type=DataType.PII,
        sensitivity=SensitivityLevel.RESTRICTED,
        replacement="[CC_REDACTED]"
    ),
    SanitizationRule(
        name="ip_addresses",
        pattern=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        data_type=DataType.METADATA,
        sensitivity=SensitivityLevel.INTERNAL,
        hash_instead=True
    ),
    
    # Infrastructure
    SanitizationRule(
        name="connection_strings",
        pattern=re.compile(r'(?:mongodb|mysql|postgres|redis|amqp)://[^\s]+'),
        data_type=DataType.CONFIG,
        sensitivity=SensitivityLevel.CONFIDENTIAL,
        replacement="[CONNECTION_STRING_REDACTED]"
    ),
    SanitizationRule(
        name="internal_urls",
        pattern=re.compile(r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s]*'),
        data_type=DataType.CONFIG,
        sensitivity=SensitivityLevel.INTERNAL,
        hash_instead=True
    ),
    
    # File paths
    SanitizationRule(
        name="absolute_paths",
        pattern=re.compile(r'(?:/home/[^/\s]+|/Users/[^/\s]+|C:\\Users\\[^\\s]+)'),
        data_type=DataType.PATH,
        sensitivity=SensitivityLevel.INTERNAL,
        replacement="[USER_PATH]"
    ),
]


@dataclass
class SanitizationResult:
    """Result of sanitization operation."""
    
    original_hash: str
    sanitized_text: str
    redactions: List[Dict[str, str]]
    sensitivity_detected: SensitivityLevel
    requires_approval: bool
    reference_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "original_hash": self.original_hash,
            "redactions_count": len(self.redactions),
            "sensitivity": self.sensitivity_detected.value,
            "requires_approval": self.requires_approval,
        }


class DataSanitizer(BaseModel):
    """
    Core data sanitization engine.
    
    Ensures all data sent to external LLMs is sanitized and safe.
    Implements the zero-data-leak principle of the data-resident architecture.
    
    Attributes:
        rules: List of sanitization rules to apply
        strict_mode: If True, reject any data with RESTRICTED sensitivity
        audit_log: Enable logging of all sanitization operations
        custom_patterns: Additional patterns to detect
    """
    
    model_config = {"arbitrary_types_allowed": True}
    
    rules: List[SanitizationRule] = Field(default_factory=lambda: DEFAULT_SANITIZATION_RULES.copy())
    strict_mode: bool = Field(default=True)
    audit_log: bool = Field(default=True)
    max_content_length: int = Field(default=50000)  # Max chars to send
    
    # Callbacks
    on_redaction: Optional[Callable[[str, str], None]] = Field(default=None)
    on_blocked: Optional[Callable[[str], None]] = Field(default=None)
    
    def sanitize(self, text: str, allow_restricted: bool = False) -> SanitizationResult:
        """
        Sanitize text for safe external transmission.
        
        Args:
            text: Text to sanitize
            allow_restricted: If True, allow restricted data (requires explicit approval)
            
        Returns:
            SanitizationResult with sanitized text and metadata
        """
        # Hash original for reference
        original_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        
        sanitized = text
        redactions = []
        max_sensitivity = SensitivityLevel.PUBLIC
        
        # Apply all rules
        for rule in self.rules:
            matches = rule.pattern.findall(sanitized)
            if matches:
                for match in matches:
                    redactions.append({
                        "rule": rule.name,
                        "type": rule.data_type.value,
                        "sensitivity": rule.sensitivity.value,
                        "match_preview": match[:20] + "..." if len(match) > 20 else match,
                    })
                    
                    if rule.sensitivity.value > max_sensitivity.value:
                        max_sensitivity = rule.sensitivity
                    
                    if self.on_redaction:
                        self.on_redaction(rule.name, match[:50])
                
                sanitized = rule.apply(sanitized)
        
        # Truncate if too long
        if len(sanitized) > self.max_content_length:
            sanitized = sanitized[:self.max_content_length] + "\n[TRUNCATED]"
        
        # Check if restricted and not allowed
        requires_approval = max_sensitivity == SensitivityLevel.RESTRICTED
        
        if self.strict_mode and requires_approval and not allow_restricted:
            if self.on_blocked:
                self.on_blocked(original_hash)
            sanitized = f"[BLOCKED: Contains restricted data. Reference: {original_hash}]"
        
        if self.audit_log:
            logger.info(
                f"Sanitized content: {len(redactions)} redactions, "
                f"sensitivity={max_sensitivity.value}, hash={original_hash}"
            )
        
        return SanitizationResult(
            original_hash=original_hash,
            sanitized_text=sanitized,
            redactions=redactions,
            sensitivity_detected=max_sensitivity,
            requires_approval=requires_approval,
        )
    
    def add_rule(self, rule: SanitizationRule) -> None:
        """Add a custom sanitization rule."""
        self.rules.append(rule)
    
    def is_safe(self, text: str) -> bool:
        """Quick check if text is safe to send externally."""
        for rule in self.rules:
            if rule.sensitivity in [SensitivityLevel.RESTRICTED, SensitivityLevel.CONFIDENTIAL]:
                if rule.pattern.search(text):
                    return False
        return True


@dataclass
class ReasoningBundle:
    """
    Sanitized reasoning bundle for LLM requests.
    
    This is what gets sent to external LLMs - NEVER raw data.
    
    Attributes:
        finding_id: Reference to the finding
        finding_type: Type of security finding
        severity: Severity level
        affected_component: Hashed or abstracted component reference
        patterns_detected: Abstract patterns (not raw code)
        policies_violated: Policy references
        context: Sanitized context metadata
    """
    
    finding_id: str
    finding_type: str
    severity: str
    affected_component: str
    patterns_detected: List[str]
    policies_violated: List[str]
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_prompt(self) -> str:
        """Convert to LLM prompt format."""
        return f"""
Security Finding Analysis Request

Finding ID: {self.finding_id}
Type: {self.finding_type}
Severity: {self.severity}
Affected Component: {self.affected_component}

Patterns Detected:
{chr(10).join(f'- {p}' for p in self.patterns_detected)}

Policies Violated:
{chr(10).join(f'- {p}' for p in self.policies_violated)}

Please provide:
1. Root cause analysis
2. Risk assessment
3. Recommended remediation steps
4. Prevention strategies
""".strip()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "affected_component": self.affected_component,
            "patterns_detected": self.patterns_detected,
            "policies_violated": self.policies_violated,
            "context": self.context,
        }


class ReasoningBundleBuilder:
    """
    Builds sanitized reasoning bundles from raw findings.
    
    Transforms customer data into safe, abstracted bundles
    that can be sent to external LLMs.
    """
    
    def __init__(self, sanitizer: Optional[DataSanitizer] = None):
        self.sanitizer = sanitizer or DataSanitizer()
        self._component_map: Dict[str, str] = {}  # Original -> Hashed
    
    def build_from_finding(
        self,
        finding_id: str,
        finding_type: str,
        severity: str,
        affected_file: str,
        code_snippet: Optional[str] = None,
        patterns: Optional[List[str]] = None,
        policies: Optional[List[str]] = None,
    ) -> ReasoningBundle:
        """
        Build a sanitized reasoning bundle from a finding.
        
        Args:
            finding_id: Finding identifier
            finding_type: Type of finding (e.g., SQL_INJECTION)
            severity: Severity level
            affected_file: The affected file path
            code_snippet: Raw code (will be sanitized!)
            patterns: Detected patterns
            policies: Violated policies
            
        Returns:
            ReasoningBundle safe for external LLM
        """
        # Hash the component path
        component_hash = self._hash_component(affected_file)
        
        # Sanitize any code if provided
        sanitized_patterns = patterns or []
        if code_snippet:
            result = self.sanitizer.sanitize(code_snippet)
            if result.redactions:
                sanitized_patterns.append(f"[Code pattern detected, {len(result.redactions)} sensitive items redacted]")
        
        return ReasoningBundle(
            finding_id=finding_id,
            finding_type=finding_type,
            severity=severity,
            affected_component=component_hash,
            patterns_detected=sanitized_patterns,
            policies_violated=policies or [],
            context={
                "file_type": affected_file.split(".")[-1] if "." in affected_file else "unknown",
                "sanitization_applied": True,
            }
        )
    
    def _hash_component(self, path: str) -> str:
        """Hash a component path for safe reference."""
        if path in self._component_map:
            return self._component_map[path]
        
        # Create a readable but anonymized reference
        file_name = path.split("/")[-1].split("\\")[-1]
        hash_suffix = hashlib.sha256(path.encode()).hexdigest()[:8]
        reference = f"{file_name}:{hash_suffix}"
        
        self._component_map[path] = reference
        return reference
    
    def get_component_mapping(self) -> Dict[str, str]:
        """Get the mapping of original paths to hashed references."""
        return self._component_map.copy()


# Convenience functions
def sanitize_for_llm(text: str, strict: bool = True) -> str:
    """
    Quick sanitization of text for LLM submission.
    
    Args:
        text: Text to sanitize
        strict: Block restricted content
        
    Returns:
        Sanitized text safe for external LLM
    """
    sanitizer = DataSanitizer(strict_mode=strict)
    result = sanitizer.sanitize(text)
    return result.sanitized_text


def create_reasoning_bundle(
    finding_id: str,
    finding_type: str,
    severity: str,
    affected_file: str,
    patterns: List[str],
    policies: List[str],
) -> ReasoningBundle:
    """
    Create a sanitized reasoning bundle.
    
    This is the safe way to prepare data for external LLM reasoning.
    """
    builder = ReasoningBundleBuilder()
    return builder.build_from_finding(
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        affected_file=affected_file,
        patterns=patterns,
        policies=policies,
    )
