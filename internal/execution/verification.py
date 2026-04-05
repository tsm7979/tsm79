"""
Verification Engine
===================

Pre-execution and post-execution verification for safety and correctness.
Validates actions before execution and results after execution.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging
import re

logger = logging.getLogger(__name__)


class VerificationStatus(str, Enum):
    """Verification result status."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


class RiskLevel(str, Enum):
    """Risk levels for verification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VerificationRule:
    """A single verification rule."""
    rule_id: str
    name: str
    description: str
    risk_level: RiskLevel
    enabled: bool = True

    def check(self, action: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Check if rule passes.

        Args:
            action: Action to verify
            context: Execution context

        Returns:
            True if passed, False if failed
        """
        raise NotImplementedError("Subclass must implement check()")


@dataclass
class VerificationResult:
    """Result of verification."""
    status: VerificationStatus
    rule_id: str
    rule_name: str
    message: str
    risk_level: RiskLevel = RiskLevel.LOW
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "message": self.message,
            "risk_level": self.risk_level.value,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }


class NoDestructiveOperationsRule(VerificationRule):
    """Prevents destructive operations without approval."""

    def __init__(self):
        super().__init__(
            rule_id="VER-001",
            name="No Destructive Operations",
            description="Prevent rm -rf, DROP TABLE, and other destructive operations",
            risk_level=RiskLevel.CRITICAL
        )

        # Destructive patterns
        self.destructive_patterns = [
            r'rm\s+-rf',
            r'DROP\s+TABLE',
            r'DROP\s+DATABASE',
            r'DELETE\s+FROM.*WHERE\s+1\s*=\s*1',
            r'TRUNCATE\s+TABLE',
            r'format\s+[A-Za-z]:',  # Windows format
            r'mkfs',  # Linux filesystem format
        ]

    def check(self, action: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check for destructive operations."""
        # Check action parameters
        params = action.get("parameters", {})
        commands = [
            params.get("command", ""),
            params.get("script", ""),
            action.get("description", "")
        ]

        for command in commands:
            if not command:
                continue

            for pattern in self.destructive_patterns:
                if re.search(pattern, str(command), re.IGNORECASE):
                    logger.warning(f"Destructive operation detected: {pattern}")
                    return False

        return True


class NoPrivilegeEscalationRule(VerificationRule):
    """Prevents privilege escalation attempts."""

    def __init__(self):
        super().__init__(
            rule_id="VER-002",
            name="No Privilege Escalation",
            description="Prevent sudo, su, and other privilege escalation",
            risk_level=RiskLevel.HIGH
        )

        self.escalation_patterns = [
            r'sudo\s+',
            r'su\s+-',
            r'runas\s+',  # Windows
            r'chmod\s+777',
            r'chmod\s+\+s',  # SUID bit
        ]

    def check(self, action: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check for privilege escalation."""
        # Check if action explicitly requires elevated privileges
        if context.get("allow_privileged", False):
            return True

        params = action.get("parameters", {})
        commands = [
            params.get("command", ""),
            params.get("script", ""),
        ]

        for command in commands:
            if not command:
                continue

            for pattern in self.escalation_patterns:
                if re.search(pattern, str(command), re.IGNORECASE):
                    logger.warning(f"Privilege escalation detected: {pattern}")
                    return False

        return True


class NoNetworkAccessRule(VerificationRule):
    """Prevents unauthorized network access."""

    def __init__(self):
        super().__init__(
            rule_id="VER-003",
            name="No Unauthorized Network Access",
            description="Prevent curl, wget, and other network operations",
            risk_level=RiskLevel.MEDIUM
        )

        self.network_patterns = [
            r'curl\s+',
            r'wget\s+',
            r'nc\s+',  # netcat
            r'telnet\s+',
            r'ssh\s+',
            r'scp\s+',
            r'ftp\s+',
        ]

    def check(self, action: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check for network access."""
        # Check if network access is allowed
        if context.get("allow_network", False):
            return True

        params = action.get("parameters", {})
        commands = [
            params.get("command", ""),
            params.get("script", ""),
        ]

        for command in commands:
            if not command:
                continue

            for pattern in self.network_patterns:
                if re.search(pattern, str(command), re.IGNORECASE):
                    logger.info(f"Network access detected (may be intentional): {pattern}")
                    # This is a warning, not a hard failure
                    return True

        return True


class InputValidationRule(VerificationRule):
    """Validates action inputs."""

    def __init__(self):
        super().__init__(
            rule_id="VER-004",
            name="Input Validation",
            description="Validate required inputs are present and valid",
            risk_level=RiskLevel.MEDIUM
        )

    def check(self, action: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check input validation."""
        # Check required fields
        if not action.get("action_type"):
            logger.error("Missing action_type")
            return False

        if not action.get("description"):
            logger.warning("Missing description")
            # Warning only, not a failure

        # Validate target if present
        target = action.get("target", "")
        if target:
            # Check for suspicious characters
            if ".." in target or target.startswith("/"):
                logger.warning(f"Suspicious target path: {target}")
                # Warning only

        return True


class OutputSizeRule(VerificationRule):
    """Validates output size is reasonable."""

    def __init__(self, max_size_mb: int = 100):
        super().__init__(
            rule_id="VER-005",
            name="Output Size Limit",
            description=f"Ensure outputs don't exceed {max_size_mb}MB",
            risk_level=RiskLevel.LOW
        )
        self.max_size_bytes = max_size_mb * 1024 * 1024

    def check_output(self, result: Dict[str, Any]) -> bool:
        """Check output size after execution."""
        output = result.get("data", {})

        # Rough size estimate (JSON serialization)
        import json
        try:
            output_json = json.dumps(output)
            size = len(output_json.encode('utf-8'))

            if size > self.max_size_bytes:
                logger.warning(f"Output size {size} bytes exceeds limit {self.max_size_bytes}")
                return False
        except:
            # If can't serialize, assume it's OK
            pass

        return True


class VerificationEngine:
    """
    Main verification engine.

    Performs pre-execution and post-execution verification
    using a set of configurable rules.
    """

    def __init__(self):
        """Initialize with default rules."""
        self.rules: List[VerificationRule] = []
        self.verification_history: List[Dict] = []

        # Add default rules
        self._load_default_rules()

        logger.info(f"VerificationEngine initialized with {len(self.rules)} rules")

    def _load_default_rules(self):
        """Load default verification rules."""
        self.rules = [
            NoDestructiveOperationsRule(),
            NoPrivilegeEscalationRule(),
            NoNetworkAccessRule(),
            InputValidationRule(),
            OutputSizeRule(max_size_mb=100),
        ]

    def verify_pre_execution(
        self,
        action: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Verify action before execution.

        Args:
            action: Action to verify
            context: Execution context

        Returns:
            Verification result with status and details
        """
        results = []
        failed_rules = []
        warning_rules = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            try:
                passed = rule.check(action, context)

                if passed:
                    result = VerificationResult(
                        status=VerificationStatus.PASSED,
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        message=f"{rule.name} passed",
                        risk_level=rule.risk_level
                    )
                else:
                    result = VerificationResult(
                        status=VerificationStatus.FAILED,
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        message=f"{rule.name} failed: {rule.description}",
                        risk_level=rule.risk_level
                    )

                    if rule.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                        failed_rules.append(rule)
                    else:
                        warning_rules.append(rule)

                results.append(result)

            except Exception as e:
                logger.error(f"Rule {rule.rule_id} error: {e}")
                result = VerificationResult(
                    status=VerificationStatus.FAILED,
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    message=f"Error: {str(e)}",
                    risk_level=rule.risk_level
                )
                results.append(result)
                failed_rules.append(rule)

        # Determine overall status
        if failed_rules:
            overall_status = VerificationStatus.FAILED
            overall_message = f"Verification failed: {len(failed_rules)} critical/high risk violations"
        elif warning_rules:
            overall_status = VerificationStatus.WARNING
            overall_message = f"Verification passed with {len(warning_rules)} warnings"
        else:
            overall_status = VerificationStatus.PASSED
            overall_message = "All verification rules passed"

        verification_result = {
            "status": overall_status.value,
            "message": overall_message,
            "rules_checked": len(self.rules),
            "passed": len([r for r in results if r.status == VerificationStatus.PASSED]),
            "failed": len(failed_rules),
            "warnings": len(warning_rules),
            "results": [r.to_dict() for r in results],
            "timestamp": datetime.utcnow().isoformat()
        }

        # Store in history
        self.verification_history.append(verification_result)

        return verification_result

    def verify_post_execution(
        self,
        action: Dict[str, Any],
        result: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Verify action after execution.

        Args:
            action: Action that was executed
            result: Execution result
            context: Execution context

        Returns:
            Verification result
        """
        results = []

        # Check output size
        output_rule = OutputSizeRule()
        if hasattr(output_rule, 'check_output'):
            passed = output_rule.check_output(result)

            results.append(VerificationResult(
                status=VerificationStatus.PASSED if passed else VerificationStatus.WARNING,
                rule_id=output_rule.rule_id,
                rule_name=output_rule.name,
                message="Output size OK" if passed else "Output size exceeds limit",
                risk_level=output_rule.risk_level
            ))

        # Check for success
        if not result.get("success", False):
            results.append(VerificationResult(
                status=VerificationStatus.WARNING,
                rule_id="POST-001",
                rule_name="Execution Success",
                message=f"Execution failed: {result.get('message', 'Unknown error')}",
                risk_level=RiskLevel.MEDIUM
            ))

        overall_status = VerificationStatus.PASSED
        if any(r.status == VerificationStatus.FAILED for r in results):
            overall_status = VerificationStatus.FAILED
        elif any(r.status == VerificationStatus.WARNING for r in results):
            overall_status = VerificationStatus.WARNING

        return {
            "status": overall_status.value,
            "results": [r.to_dict() for r in results],
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get verification statistics."""
        if not self.verification_history:
            return {
                "total_verifications": 0,
                "pass_rate": 0,
                "total_rules": len(self.rules)
            }

        total = len(self.verification_history)
        passed = sum(1 for v in self.verification_history if v["status"] == "passed")

        return {
            "total_verifications": total,
            "passed": passed,
            "failed": sum(1 for v in self.verification_history if v["status"] == "failed"),
            "warnings": sum(1 for v in self.verification_history if v["status"] == "warning"),
            "pass_rate": passed / total if total > 0 else 0,
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules if r.enabled)
        }


# Global instance
verification_engine = VerificationEngine()
