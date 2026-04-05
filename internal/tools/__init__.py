"""
TSM Layer Tools
===============

Tool manifest system for executing security playbooks and workflows.
Connects 18+ security playbooks to executable tools.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ToolType(str, Enum):
    """Types of tools."""
    SCANNER = "scanner"
    ANALYZER = "analyzer"
    FIXER = "fixer"
    DEPLOYER = "deployer"
    VALIDATOR = "validator"


@dataclass
class ToolManifest:
    """
    Tool manifest defining tool capabilities.

    Maps security playbooks and workflows to executable tools.
    """
    tool_id: str
    name: str
    description: str
    tool_type: ToolType

    # Capabilities
    finding_types: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)

    # Execution
    playbook_id: Optional[str] = None
    requires_approval: bool = False

    # Metadata
    version: str = "1.0.0"
    confidence: float = 0.9

    def matches(self, finding_type: str, language: str = None, framework: str = None) -> bool:
        """Check if tool matches the given criteria."""
        if finding_type not in self.finding_types:
            return False

        if language and self.languages and language not in self.languages:
            return False

        if framework and self.frameworks and framework not in self.frameworks:
            return False

        return True


class ToolRegistry:
    """
    Registry of available tools.

    Manages tool discovery, selection, and execution.
    Integrates 18+ security playbooks as executable tools.
    """

    def __init__(self):
        self.tools: Dict[str, ToolManifest] = {}
        self._load_default_tools()
        logger.info(f"ToolRegistry initialized with {len(self.tools)} tools")

    def _load_default_tools(self):
        """Load default tool manifests from playbooks."""
        try:
            from learning.playbooks.extended_playbooks import get_extended_playbooks

            # Convert playbooks to tool manifests
            playbooks = get_extended_playbooks()

            for playbook in playbooks:
                tool = ToolManifest(
                    tool_id=playbook.playbook_id,
                    name=f"Fix {playbook.finding_type}",
                    description=playbook.fix_strategy.description,
                    tool_type=ToolType.FIXER,
                    finding_types=[playbook.finding_type],
                    languages=[playbook.language] if playbook.language else [],
                    frameworks=[playbook.framework] if playbook.framework else [],
                    playbook_id=playbook.playbook_id,
                    requires_approval=(playbook.approval_policy.value == "manual"),
                    confidence=playbook.confidence
                )
                self.tools[tool.tool_id] = tool

            logger.info(f"Loaded {len(playbooks)} playbook-based tools")
        except Exception as e:
            logger.warning(f"Could not load playbooks: {e}")

        # Add scanner tools
        self._add_scanner_tools()

    def _add_scanner_tools(self):
        """Add built-in scanner tools."""
        scanners = [
            ToolManifest(
                tool_id="SCAN-SECURITY-001",
                name="Security Scanner",
                description="Scan files for security vulnerabilities",
                tool_type=ToolType.SCANNER,
                finding_types=["ALL"],
                confidence=0.95
            ),
            ToolManifest(
                tool_id="SCAN-COMPLIANCE-001",
                name="Compliance Scanner",
                description="Check compliance with security frameworks",
                tool_type=ToolType.SCANNER,
                finding_types=["COMPLIANCE"],
                confidence=0.90
            ),
            ToolManifest(
                tool_id="SCAN-VULN-001",
                name="Vulnerability Scanner",
                description="Scan for known vulnerabilities",
                tool_type=ToolType.SCANNER,
                finding_types=["VULNERABILITY"],
                confidence=0.92
            ),
        ]

        for scanner in scanners:
            self.tools[scanner.tool_id] = scanner

    def find_tools(
        self,
        finding_type: str,
        language: str = None,
        framework: str = None,
        tool_type: ToolType = None
    ) -> List[ToolManifest]:
        """
        Find tools matching criteria.

        Args:
            finding_type: Type of finding (e.g., "SQL_INJECTION")
            language: Programming language (e.g., "python")
            framework: Framework (e.g., "django")
            tool_type: Type of tool (e.g., ToolType.FIXER)

        Returns:
            List of matching tool manifests
        """
        matches = []

        for tool in self.tools.values():
            if tool_type and tool.tool_type != tool_type:
                continue

            if tool.matches(finding_type, language, framework):
                matches.append(tool)

        # Sort by confidence
        matches.sort(key=lambda t: t.confidence, reverse=True)

        return matches

    def get_tool(self, tool_id: str) -> Optional[ToolManifest]:
        """Get a specific tool by ID."""
        return self.tools.get(tool_id)

    async def execute(
        self,
        tool_name: str,
        inputs: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a tool.

        Args:
            tool_name: Tool ID or name
            inputs: Tool inputs
            context: Execution context

        Returns:
            Tool execution result
        """
        tool = self.get_tool(tool_name)

        if not tool:
            return {
                "success": False,
                "error": f"Tool not found: {tool_name}"
            }

        logger.info(f"Executing tool: {tool.name} ({tool.tool_id})")

        # Route to appropriate executor
        if tool.tool_type == ToolType.SCANNER:
            return await self._execute_scanner(tool, inputs, context)
        elif tool.tool_type == ToolType.FIXER:
            return await self._execute_fixer(tool, inputs, context)
        else:
            return {
                "success": False,
                "error": f"Tool type not implemented: {tool.tool_type}"
            }

    async def _execute_scanner(
        self,
        tool: ToolManifest,
        inputs: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute scanner tool via ActionExecutor."""
        from execution.action_executor import ActionExecutor, Action, ActionType

        executor = ActionExecutor(simulation_mode=False)

        action = Action(
            action_type=ActionType.SCAN.value,
            description=f"{tool.name}: {inputs.get('input', '')}",
            target=context.get("target", "."),
            parameters=inputs,
            risk_level="low"
        )

        result = await executor.execute(action)

        return {
            "success": result.success,
            "tool": tool.name,
            "data": result.data,
            "message": result.message
        }

    async def _execute_fixer(
        self,
        tool: ToolManifest,
        inputs: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute fixer tool via PlaybookEngine."""
        from learning.playbooks.engine import PlaybookEngine

        # Get playbook
        if not tool.playbook_id:
            return {
                "success": False,
                "error": "No playbook associated with tool"
            }

        engine = PlaybookEngine(storage_path="data/learning")
        playbook = engine.get_playbook(tool.playbook_id)

        if not playbook:
            return {
                "success": False,
                "error": f"Playbook not found: {tool.playbook_id}"
            }

        # Apply playbook
        fix_result = {
            "success": True,
            "tool": tool.name,
            "playbook_id": tool.playbook_id,
            "fix_strategy": playbook.fix_strategy.description,
            "code_template": playbook.fix_strategy.fix_template,
            "confidence": playbook.confidence
        }

        return fix_result

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        stats = {
            "total_tools": len(self.tools),
            "by_type": {},
            "by_finding_type": {},
        }

        for tool in self.tools.values():
            # Count by type
            tool_type = tool.tool_type.value
            stats["by_type"][tool_type] = stats["by_type"].get(tool_type, 0) + 1

            # Count by finding type
            for finding_type in tool.finding_types:
                stats["by_finding_type"][finding_type] = stats["by_finding_type"].get(finding_type, 0) + 1

        return stats


# Global registry
tool_registry = ToolRegistry()
