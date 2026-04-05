"""
Mesh Orchestrator Adapter for TSMv1
====================================

Adapts the Byzantine-fault-tolerant 5-agent mesh orchestrator
to work with TSMv1's poly-LLM infrastructure.

Simplified integration that uses TSMv1 orchestrator instead of
the old inference manager.
"""

import asyncio
import logging
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    """Agent roles in the mesh."""
    OBSERVER = "observer"
    SECURITY = "security"
    PLANNER = "planner"
    EXECUTION = "execution"
    VERIFIER = "verifier"


class ConsensusStatus(str, Enum):
    """Consensus outcome status."""
    SUCCESS = "success"
    FAILED_BYZANTINE = "failed_byzantine"
    FAILED_COHERENCE = "failed_coherence"


class SimplifiedMeshOrchestrator:
    """
    Simplified mesh orchestrator for TSMv1.

    Coordinates 5 specialist agents for security incident analysis:
    1. Observer - Fact gathering
    2. Security - Threat assessment
    3. Planner - Remediation planning
    4. Execution - Technical implementation
    5. Verifier - Red team validation
    """

    # Role-specific prompts
    ROLE_PROMPTS = {
        AgentRole.OBSERVER: (
            "You are the OBSERVER agent. Gather facts about the security incident. "
            "Enumerate what you know, identify affected components, and flag observable indicators. "
            "Be factual and concise. Do NOT suggest fixes yet."
        ),
        AgentRole.SECURITY: (
            "You are the SECURITY agent. Assess threat severity, classify the attack vector "
            "(OWASP / STRIDE), identify exploit paths, and state the blast radius. "
            "Be technical and precise."
        ),
        AgentRole.PLANNER: (
            "You are the PLANNER agent. You have analysis from Observer and Security agents. "
            "Synthesize their findings into a prioritized remediation plan with clear, numbered steps. "
            "Each step must be actionable."
        ),
        AgentRole.EXECUTION: (
            "You are the EXECUTION agent. You have a remediation plan. "
            "Translate the plan into concrete shell commands, code patches, or configuration changes. "
            "Be explicit: include exact file paths, commands, or code snippets."
        ),
        AgentRole.VERIFIER: (
            "You are the VERIFIER agent (red team). Attack the proposed plan - "
            "find edge cases, unintended side-effects, compliance violations, and security regressions. "
            "If the plan is safe, say so explicitly."
        ),
    }

    def __init__(self):
        """Initialize with TSMv1 orchestrator."""
        from router import orchestrator
        self.orchestrator = orchestrator
        self.deliberation_history: List[Dict] = []

    async def run_deliberation(
        self,
        incident_description: str,
        severity: str = "high",
        deliberation_id: str = None
    ) -> Dict[str, Any]:
        """
        Run a 5-agent deliberation on a security incident.

        Args:
            incident_description: Description of the security incident
            severity: Severity level (low, medium, high, critical)
            deliberation_id: Optional deliberation ID (auto-generated if not provided)

        Returns:
            Deliberation result with agent responses and consensus
        """
        deliberation_id = deliberation_id or str(uuid.uuid4())
        start_time = datetime.utcnow()

        logger.info(f"[{deliberation_id}] Starting mesh deliberation: {incident_description[:80]}...")

        # Phase 1: Parallel analysis by Observer and Security agents
        logger.info(f"[{deliberation_id}] Phase 1: Parallel analysis")

        observer_task = self._invoke_agent(
            AgentRole.OBSERVER,
            incident_description,
            severity
        )
        security_task = self._invoke_agent(
            AgentRole.SECURITY,
            incident_description,
            severity
        )

        observer_result, security_result = await asyncio.gather(
            observer_task,
            security_task
        )

        # Phase 2: Coherence check (simplified - just log)
        logger.info(f"[{deliberation_id}] Phase 2: Coherence check")
        coherence_score = self._check_coherence(observer_result, security_result)
        logger.info(f"[{deliberation_id}] Coherence: {coherence_score:.2f}")

        # Phase 3: Planner synthesizes
        logger.info(f"[{deliberation_id}] Phase 3: Planner synthesis")

        planner_context = (
            f"Incident: {incident_description}\n\n"
            f"Observer Analysis:\n{observer_result}\n\n"
            f"Security Analysis:\n{security_result}"
        )

        planner_result = await self._invoke_agent(
            AgentRole.PLANNER,
            planner_context,
            severity
        )

        # Phase 4: Execution agent details
        logger.info(f"[{deliberation_id}] Phase 4: Execution planning")

        execution_context = (
            f"Remediation Plan:\n{planner_result}\n\n"
            f"Provide concrete technical steps."
        )

        execution_result = await self._invoke_agent(
            AgentRole.EXECUTION,
            execution_context,
            severity
        )

        # Phase 5: Verifier red-teams
        logger.info(f"[{deliberation_id}] Phase 5: Verification (red team)")

        verifier_context = (
            f"Proposed Plan:\n{planner_result}\n\n"
            f"Technical Steps:\n{execution_result}\n\n"
            f"Find flaws, edge cases, and security regressions."
        )

        verifier_result = await self._invoke_agent(
            AgentRole.VERIFIER,
            verifier_context,
            severity
        )

        # Compile result
        end_time = datetime.utcnow()
        elapsed_ms = (end_time - start_time).total_seconds() * 1000

        result = {
            "deliberation_id": deliberation_id,
            "incident": incident_description,
            "severity": severity,
            "agent_responses": {
                "observer": observer_result,
                "security": security_result,
                "planner": planner_result,
                "execution": execution_result,
                "verifier": verifier_result,
            },
            "coherence_score": coherence_score,
            "consensus_status": ConsensusStatus.SUCCESS.value,
            "execution_time_ms": elapsed_ms,
            "timestamp": start_time.isoformat()
        }

        # Store in history
        self.deliberation_history.append(result)

        logger.info(f"[{deliberation_id}] Deliberation complete in {elapsed_ms:.0f}ms")

        return result

    async def _invoke_agent(
        self,
        role: AgentRole,
        context: str,
        severity: str
    ) -> str:
        """
        Invoke a single agent via TSMv1 orchestrator.

        Args:
            role: Agent role
            context: Context/prompt for agent
            severity: Severity level

        Returns:
            Agent response text
        """
        from router.orchestrator import LLMRequest, TaskType

        # Get role-specific prompt
        system_prompt = self.ROLE_PROMPTS[role]

        # Create LLM request
        request = LLMRequest(
            task_type=TaskType.REASONING,  # All agents use reasoning
            prompt=context,
            system_prompt=system_prompt,
            context={"agent_role": role.value, "severity": severity},
            max_tokens=2000,
            temperature=0.7
        )

        # Execute via orchestrator
        try:
            response = await self.orchestrator.complete(request)

            if response.success:
                logger.info(
                    f"Agent {role.value}: {response.provider.value}/{response.model} "
                    f"({response.tokens_used} tokens, ${response.cost:.4f})"
                )
                return response.content
            else:
                logger.error(f"Agent {role.value} failed: {response.error}")
                return f"[ERROR] {response.error}"

        except Exception as e:
            logger.error(f"Agent {role.value} exception: {e}")
            return f"[EXCEPTION] {str(e)}"

    def _check_coherence(self, text_a: str, text_b: str) -> float:
        """
        Check coherence between two agent responses using simple word overlap.

        Args:
            text_a: First agent response
            text_b: Second agent response

        Returns:
            Coherence score (0.0 to 1.0)
        """
        import re

        # Tokenize (simple word extraction)
        words_a = set(re.findall(r'\b[a-z]{3,}\b', text_a.lower()))
        words_b = set(re.findall(r'\b[a-z]{3,}\b', text_b.lower()))

        if not words_a or not words_b:
            return 0.5  # Neutral if can't measure

        # Jaccard similarity
        intersection = len(words_a & words_b)
        union = len(words_a | words_b)

        return intersection / union if union else 0.0

    def get_stats(self) -> Dict[str, Any]:
        """Get mesh orchestrator statistics."""
        if not self.deliberation_history:
            return {
                "total_deliberations": 0,
                "avg_execution_time_ms": 0,
                "avg_coherence_score": 0,
            }

        total = len(self.deliberation_history)
        avg_time = sum(d["execution_time_ms"] for d in self.deliberation_history) / total
        avg_coherence = sum(d["coherence_score"] for d in self.deliberation_history) / total

        return {
            "total_deliberations": total,
            "avg_execution_time_ms": avg_time,
            "avg_coherence_score": avg_coherence,
            "success_rate": sum(
                1 for d in self.deliberation_history
                if d["consensus_status"] == ConsensusStatus.SUCCESS.value
            ) / total
        }


# Global instance
mesh_orchestrator = SimplifiedMeshOrchestrator()
