"""
MeshOrchestrator — Byzantine-Fault-Tolerant 5-Agent Deliberation Engine.

Flow:
  Phase 1  Observer + Security analyse incident in parallel
  Phase 2  CoherenceEngine: if Jaccard(obs, sec) < 0.70 → Planner mediates
  Phase 3  Planner synthesises analysis into action plan
  Phase 4  Execution agent details concrete technical steps
  Phase 5  Verifier red-teams the plan (adversarial probe)

Byzantine detection:
  Each agent returns a JSON block with a `confidence` field (0.0–1.0).
  If |agent_conf - mean_conf| > 0.30 → mark is_byzantine_flagged = True.
  Flagged responses are excluded from the weighted consensus score.

Weighted consensus:
  score = Σ(confidence_i × trust_score_i) / n_unflagged

Streaming:
  Events are pushed to a per-deliberation asyncio.Queue (imported from
  websocket.py) so the WebSocket endpoint can stream them to the browser.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# from src.core.llm.inference_manager import InferenceManager, get_inference_manager
from src.api.schemas.mesh import AgentRole, ConsensusStatus

logger = logging.getLogger(__name__)

# Module-level deliberation event queues — shared with websocket.py
_deliberation_queues: Dict[str, asyncio.Queue] = {}


def get_deliberation_queue(deliberation_id: str) -> asyncio.Queue:
    if deliberation_id not in _deliberation_queues:
        _deliberation_queues[deliberation_id] = asyncio.Queue(maxsize=200)
    return _deliberation_queues[deliberation_id]


def push_deliberation_event(deliberation_id: str, event: Dict[str, Any]) -> None:
    """Called by MeshOrchestrator to push events; consumed by WS endpoint."""
    q = get_deliberation_queue(deliberation_id)
    try:
        q.put_nowait(event)
    except asyncio.QueueFull:
        logger.warning("Deliberation queue full for %s — dropping event", deliberation_id)


# ── Role-specific system prompts ──────────────────────────────────────────────

_ROLE_PROMPTS: Dict[AgentRole, str] = {
    AgentRole.OBSERVER: (
        "You are the OBSERVER agent in a sovereign security AI mesh. "
        "Your role: gather facts, enumerate what you know about the incident, "
        "identify affected components, and flag observable indicators. "
        "Be factual and concise. Do NOT suggest fixes yet."
    ),
    AgentRole.SECURITY: (
        "You are the SECURITY agent in a sovereign security AI mesh. "
        "Your role: assess the threat severity, classify the attack vector "
        "(OWASP / STRIDE), identify exploit paths, and state the blast radius. "
        "Be technical and precise."
    ),
    AgentRole.PLANNER: (
        "You are the PLANNER agent in a sovereign security AI mesh. "
        "You have received analysis from Observer and Security agents. "
        "Your role: synthesise their findings into a prioritised remediation plan "
        "with clear, numbered steps. Each step must be actionable."
    ),
    AgentRole.EXECUTION: (
        "You are the EXECUTION agent in a sovereign security AI mesh. "
        "You have a remediation plan. Your role: translate the plan into "
        "concrete shell commands, code patches, or configuration changes. "
        "Be explicit: include exact file paths, commands, or code snippets."
    ),
    AgentRole.VERIFIER: (
        "You are the VERIFIER agent in a sovereign security AI mesh. "
        "You are a red-team adversary. Your role: attack the proposed plan — "
        "find edge cases, unintended side-effects, compliance violations, "
        "and security regressions. If the plan is safe, say so explicitly."
    ),
}

_STRUCTURED_SUFFIX = """

Respond ONLY with a JSON object in this exact format (no markdown, no extra text):
{"reasoning": "<your full chain-of-thought>", "proposed_action": {"summary": "<1-2 sentences>", "details": "<specifics>"}, "confidence": <float 0.0-1.0>}
"""


# ── Coherence Engine ──────────────────────────────────────────────────────────

class CoherenceEngine:
    """
    Measures semantic alignment between two text responses using Jaccard
    similarity on word tokens (no external dependencies required).
    """

    @staticmethod
    def _tokenize(text: str) -> set:
        words = re.findall(r"\b[a-z]{3,}\b", text.lower())
        return set(words)

    @classmethod
    def similarity(cls, text_a: str, text_b: str) -> float:
        """Return Jaccard similarity in [0, 1]."""
        a = cls._tokenize(text_a)
        b = cls._tokenize(text_b)
        if not a or not b:
            return 0.5  # can't measure — neutral
        intersection = len(a & b)
        union = len(a | b)
        return intersection / union if union else 0.0


# ── Agent response model ──────────────────────────────────────────────────────

class _AgentResult:
    __slots__ = (
        "role", "reasoning_chain", "proposed_action",
        "confidence", "is_byzantine_flagged", "trust_score", "created_at",
    )

    def __init__(
        self,
        role: AgentRole,
        reasoning_chain: str,
        proposed_action: Dict[str, Any],
        confidence: float,
        trust_score: float = 1.0,
    ) -> None:
        self.role = role
        self.reasoning_chain = reasoning_chain
        self.proposed_action = proposed_action
        self.confidence = confidence
        self.is_byzantine_flagged = False
        self.trust_score = trust_score
        self.created_at = datetime.now(timezone.utc)

    def to_event_payload(self) -> Dict[str, Any]:
        return {
            "agentRole":          self.role.value,
            "content":            self.reasoning_chain[:800],  # truncate for WS
            "proposedAction":     self.proposed_action,
            "confidence":         round(self.confidence, 3),
            "isByzantineFlagged": self.is_byzantine_flagged,
            "timestamp":          self.created_at.isoformat(),
        }


# ── MeshOrchestrator ──────────────────────────────────────────────────────────

class MeshOrchestrator:
    """
    Coordinates all five specialist agents through a single deliberation cycle.

    Usage::

        orch = MeshOrchestrator()
        result = await orch.run_deliberation(
            deliberation_id="<uuid>",
            incident_description="SQL injection in /auth endpoint",
            severity="critical",
        )
    """

    COHERENCE_THRESHOLD   = 0.70   # below this → Planner mediates
    BYZANTINE_THRESHOLD   = 0.30   # |conf - mean| above this → flagged
    MIN_CONSENSUS_SCORE   = 0.65   # below this → FAILED_BYZANTINE

    # LLM priority by phase
    _PHASE_PRIORITY: Dict[AgentRole, int] = {
        AgentRole.OBSERVER:  2,
        AgentRole.SECURITY:  1,   # security analysis is high priority
        AgentRole.PLANNER:   2,
        AgentRole.EXECUTION: 2,
        AgentRole.VERIFIER:  3,
    }

    def __init__(
        self,
        inference_manager: Optional[InferenceManager] = None,
        db_session=None,
    ) -> None:
        self._im = inference_manager or get_inference_manager()
        self._db = db_session  # Optional AsyncSession for DB persistence

    # ── Public entry point ─────────────────────────────────────────────────────

    async def run_deliberation(
        self,
        deliberation_id: str,
        incident_description: str,
        severity: str = "high",
        existing_analysis: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute the full 5-phase deliberation and return a summary dict.

        Events are also streamed to _deliberation_queues[deliberation_id].
        """
        logger.info(
            "Starting deliberation %s [%s] — %s",
            deliberation_id[:8], severity, incident_description[:60],
        )

        self._emit(deliberation_id, "CONSENSUS_UPDATE", {
            "status": ConsensusStatus.DEBATING.value,
            "message": "Agentic mesh initialised — beginning analysis",
        })

        context = {
            "incident":  incident_description,
            "severity":  severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # ── Phase 1: Parallel observation + security analysis ─────────────────
        obs_result, sec_result = await asyncio.gather(
            self._query_agent(AgentRole.OBSERVER,  context, deliberation_id),
            self._query_agent(AgentRole.SECURITY,  context, deliberation_id),
        )
        responses: List[_AgentResult] = [obs_result, sec_result]

        # ── Phase 2: CoherenceEngine check ────────────────────────────────────
        coherence = CoherenceEngine.similarity(
            obs_result.reasoning_chain,
            sec_result.reasoning_chain,
        )
        logger.info("Coherence score: %.3f", coherence)

        if coherence < self.COHERENCE_THRESHOLD:
            logger.warning(
                "Low coherence (%.3f < %.3f) — Planner mediating conflict",
                coherence, self.COHERENCE_THRESHOLD,
            )
            mediation_context = {
                **context,
                "observer_findings": obs_result.reasoning_chain,
                "security_findings": sec_result.reasoning_chain,
                "note": "Observer and Security disagree — synthesise their views before planning.",
            }
            plan_result = await self._query_agent(
                AgentRole.PLANNER, mediation_context, deliberation_id, priority=1
            )
        else:
            plan_context = {
                **context,
                "observer_findings": obs_result.reasoning_chain,
                "security_findings": sec_result.reasoning_chain,
            }
            plan_result = await self._query_agent(
                AgentRole.PLANNER, plan_context, deliberation_id
            )
        responses.append(plan_result)

        # ── Phase 3: Execution details ────────────────────────────────────────
        exec_context = {
            **context,
            "remediation_plan": plan_result.reasoning_chain,
        }
        exec_result = await self._query_agent(
            AgentRole.EXECUTION, exec_context, deliberation_id
        )
        responses.append(exec_result)

        # ── Phase 4: Verifier red-teams the plan ──────────────────────────────
        verify_context = {
            **context,
            "proposed_plan":        plan_result.reasoning_chain,
            "execution_steps":      exec_result.reasoning_chain,
        }
        verify_result = await self._query_agent(
            AgentRole.VERIFIER, verify_context, deliberation_id
        )
        responses.append(verify_result)

        # ── Phase 5: Byzantine detection + consensus ──────────────────────────
        self._apply_byzantine_detection(responses)
        consensus_score = self._compute_weighted_consensus(responses)
        final_status = (
            ConsensusStatus.ACHIEVED
            if consensus_score >= self.MIN_CONSENSUS_SCORE
            else ConsensusStatus.FAILED_BYZANTINE
        )

        final_plan = {
            "plan_summary":    plan_result.proposed_action,
            "execution_steps": exec_result.proposed_action,
            "verifier_notes":  verify_result.proposed_action,
            "consensus_score": round(consensus_score, 3),
        }

        self._emit(deliberation_id, "CONSENSUS_UPDATE", {
            "status":          final_status.value,
            "coherence_score": round(coherence, 3),
            "consensus_score": round(consensus_score, 3),
            "final_plan":      final_plan,
        })

        # ── Persist to DB (optional) ──────────────────────────────────────────
        if self._db is not None:
            await self._persist(
                deliberation_id, responses, final_status, coherence, final_plan
            )

        return {
            "deliberation_id": deliberation_id,
            "status":          final_status.value,
            "coherence_score": round(coherence, 3),
            "consensus_score": round(consensus_score, 3),
            "final_plan":      final_plan,
            "responses":       [r.to_event_payload() for r in responses],
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    async def _query_agent(
        self,
        role: AgentRole,
        context: Dict[str, Any],
        deliberation_id: str,
        priority: int = 3,
    ) -> _AgentResult:
        system_prompt = _ROLE_PROMPTS[role]
        context_str = json.dumps(context, indent=2, default=str)
        prompt = (
            f"{system_prompt}\n\n"
            f"INCIDENT CONTEXT:\n{context_str}\n"
            f"{_STRUCTURED_SUFFIX}"
        )

        priority = self._PHASE_PRIORITY.get(role, priority)

        try:
            raw = await self._im.generate_prioritized(
                prompt=prompt,
                priority=priority,
                max_tokens=600,
            )
            text = raw.get("text", "")
            parsed = self._parse_agent_json(text)
        except Exception as exc:
            logger.error("Agent %s failed: %s", role.value, exc)
            parsed = {
                "reasoning":       f"Agent error: {exc}",
                "proposed_action": {"summary": "Agent unavailable", "details": str(exc)},
                "confidence":      0.3,
            }

        result = _AgentResult(
            role=role,
            reasoning_chain=parsed.get("reasoning", text[:400] if 'text' in locals() else ""),
            proposed_action=parsed.get("proposed_action", {}),
            confidence=float(parsed.get("confidence", 0.5)),
        )

        # Stream event to WebSocket subscribers
        self._emit(deliberation_id, "AGENT_THOUGHT", result.to_event_payload())
        return result

    @staticmethod
    def _parse_agent_json(text: str) -> Dict[str, Any]:
        """Extract JSON from LLM response (handles markdown fences)."""
        # Strip markdown code fences
        text = re.sub(r"```(?:json)?", "", text).strip()
        # Find first { ... } block
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        # Fallback — wrap raw text
        return {
            "reasoning":       text[:600],
            "proposed_action": {"summary": text[:200]},
            "confidence":      0.5,
        }

    def _apply_byzantine_detection(self, responses: List[_AgentResult]) -> None:
        confidences = [r.confidence for r in responses]
        if not confidences:
            return
        mean_conf = sum(confidences) / len(confidences)
        for r in responses:
            if abs(r.confidence - mean_conf) > self.BYZANTINE_THRESHOLD:
                r.is_byzantine_flagged = True
                logger.warning(
                    "Byzantine flag: %s (conf=%.2f, mean=%.2f)",
                    r.role.value, r.confidence, mean_conf,
                )

    @staticmethod
    def _compute_weighted_consensus(responses: List[_AgentResult]) -> float:
        valid = [r for r in responses if not r.is_byzantine_flagged]
        if not valid:
            return 0.0
        total = sum(r.confidence * r.trust_score for r in valid)
        return total / len(valid)

    @staticmethod
    def _emit(deliberation_id: str, event_type: str, payload: Dict[str, Any]) -> None:
        push_deliberation_event(deliberation_id, {
            "type":    event_type,
            "payload": payload,
        })

    async def _persist(
        self,
        deliberation_id: str,
        responses: List[_AgentResult],
        status: ConsensusStatus,
        coherence: float,
        final_plan: Dict[str, Any],
    ) -> None:
        """Write deliberation + agent responses to PostgreSQL."""
        try:
            from sqlalchemy import text  # noqa: PLC0415

            async with self._db() as session:
                await session.execute(
                    text("""
                        UPDATE mesh_deliberations
                        SET status = :status,
                            coherence_score = :coherence,
                            final_plan = :plan,
                            closed_at = NOW()
                        WHERE id = :id
                    """),
                    {
                        "id":       deliberation_id,
                        "status":   status.value,
                        "coherence": coherence,
                        "plan":     json.dumps(final_plan),
                    },
                )
                for r in responses:
                    await session.execute(
                        text("""
                            INSERT INTO agent_responses
                              (deliberation_id, agent_role, reasoning_chain,
                               proposed_action, confidence_level,
                               is_byzantine_flagged, trust_score)
                            VALUES
                              (:did, :role, :chain, :action, :conf, :byz, :trust)
                        """),
                        {
                            "did":   deliberation_id,
                            "role":  r.role.value,
                            "chain": r.reasoning_chain,
                            "action": json.dumps(r.proposed_action),
                            "conf":  r.confidence,
                            "byz":   r.is_byzantine_flagged,
                            "trust": r.trust_score,
                        },
                    )
                await session.commit()
        except Exception as exc:
            logger.error("Failed to persist deliberation to DB: %s", exc)


# ── Global instance ────────────────────────────────────────────────────────────

_orchestrator: Optional[MeshOrchestrator] = None


def get_mesh_orchestrator(db_session=None) -> MeshOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = MeshOrchestrator(db_session=db_session)
    elif db_session is not None:
        _orchestrator._db = db_session
    return _orchestrator
