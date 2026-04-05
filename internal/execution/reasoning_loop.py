# backend/src/core/agentic/reasoning_loop.py

"""
Continuous reasoning loop for autonomous agents.

Implements Chain-of-Thought reasoning, self-correction, and iterative refinement.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from router.orchestrator import PolyLLMOrchestrator as LLMRouter, TaskType
from execution.memory_manager import MemoryManager
from learning.playbooks.engine import PlaybookEngine

logger = logging.getLogger(__name__)


@dataclass
class ReasoningStep:
    """A single step in a reasoning plan."""
    
    step_number: int
    description: str
    action_type: str  # e.g., "scan", "fix", "analyze", "report"
    parameters: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "low"  # low, medium, high
    dependencies: List[int] = field(default_factory=list)  # step numbers this depends on
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "step_number": self.step_number,
            "description": self.description,
            "action_type": self.action_type,
            "parameters": self.parameters,
            "risk_level": self.risk_level,
            "dependencies": self.dependencies,
        }


@dataclass
class ReasoningPlan:
    """A complete reasoning plan with multiple steps."""
    
    goal: str
    steps: List[ReasoningStep]
    reasoning: str  # The LLM's reasoning process
    confidence: float  # 0-1
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "goal": self.goal,
            "steps": [s.to_dict() for s in self.steps],
            "reasoning": self.reasoning,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
        }


class ReasoningLoop:
    """
    Implements autonomous reasoning with Chain-of-Thought.
    
    Features:
    - Multi-step planning
    - Self-correction
    - Iterative refinement
    - Confidence scoring
    """
    
    def __init__(self, llm_router: LLMRouter, memory_manager: Optional[MemoryManager] = None):
        """Initialize reasoning loop."""
        self.llm_router = llm_router
        self.memory_manager = memory_manager
        self.playbook_engine = PlaybookEngine()
    
    async def generate_plan(
        self,
        goal: str,
        context: Dict[str, Any],
        temperature: float = 0.7,
        max_steps: int = 10,
    ) -> ReasoningPlan:
        """
        Generate a multi-step plan to achieve a goal.
        
        Args:
            goal: The objective to achieve
            context: Current context (signals, memory, etc.)
            temperature: LLM temperature for reasoning
            max_steps: Maximum number of steps in the plan
            
        Returns:
            Complete reasoning plan
        """
        # RAG: Fetch relevant past episodes
        past_episodes = []
        if self.memory_manager:
            past_episodes = self.memory_manager.find_similar_episodes(goal, limit=3)

        past_experience_str = ""
        if past_episodes:
            past_experience_str = "RELEVANT PAST EXPERIENCE:\n"
            for ep in past_episodes:
                past_experience_str += f"- Incident {ep.incident_id}: {ep.final_outcome}\n"
                for snapshot in ep.episodes:
                     past_experience_str += f"  * Action: {snapshot.action_taken} -> Outcome: {snapshot.outcome}\n"

        # Connect to RAG/Memory context
        # Extract RAG results from recent perceptions to make them prominent
        rag_context_str = ""
        try:
            perceptions = context.get("recent_perceptions", [])
            if perceptions:
                # Get most recent perception
                latest = perceptions[-1]
                signals = latest.get("signals", {})
                rag_results = signals.get("rag_results", [])
                
                if rag_results:
                    rag_context_str = "RETRIEVED KNOWLEDGE (RAG):\n"
                    for i, res in enumerate(rag_results):
                        content = res.get("content", "")[:5000] # Truncate if too long
                        source = res.get("source", "unknown")
                        rag_context_str += f"Source {i+1} ({source}):\n{content}\n---\n"
        except Exception as e:
            logger.warning(f"Failed to extract RAG context: {e}")

        # LEARNING: Check for Playbooks
        playbook_context_str = ""
        try:
             # Infer finding type from goal - simple heuristic for now
             finding_type = "general"
             if "fix" in goal.lower():
                 finding_type = "fix_request"
             
             match = self.playbook_engine.find_matching_playbook(finding_type, context)
             if match and match.use_playbook:
                 playbook_context_str = f"""
RECOMMENDED STRATEGY (High Confidence):
Name: {match.playbook.playbook_id}
Strategy: {match.playbook.fix_strategy.description}
Code Pattern: {match.playbook.fix_strategy.code_pattern}
Template: {match.playbook.fix_strategy.fix_template}
Confidence: {match.playbook.confidence}
"""
                 if match.playbook.can_auto_apply:
                      playbook_context_str += "\nNOTE: This strategy is verified for AUTO-APPLICATION."
        except Exception as e:
            logger.warning(f"Playbook lookup failed: {e}")

        # Format context for LLM
        context_str = "\n".join([f"{k}: {v}" for k, v in context.items()])
        
        prompt = f"""You are an autonomous security operations agent. Generate a detailed plan to achieve the following goal.
1. Answer the user's question directly if you have the information.
2. Formulate a plan if actions are needed.

GOAL: {goal}

{past_experience_str}

{rag_context_str}
{playbook_context_str}

CURRENT CONTEXT:
{context_str}

Generate a step-by-step plan. For each step, provide:
1. Step number
2. Clear description
3. Action type (scan/analyze/fix/report/configure)
4. Risk level (low/medium/high)
5. Any dependencies on previous steps

Think through this carefully. Consider:
- What information do we need?
- What are the dependencies?
- What could go wrong?
- What approvals might be needed?
- How can we apply lessons from past experience?
- IF A PLAYBOOK IS RECOMMENDED: Prioritize using that strategy as it is verified.
- IF RAG CONTEXT IS PRESENT: Use it to answer the user's question directly in the plan or reflection.

Format your response as a structured plan with clear steps.
Maximum {max_steps} steps.
"""
        
        # Extract user_id from context for optimization
        user_id = "anonymous"
        try:
            perceptions = context.get("recent_perceptions", [])
            if perceptions:
                latest = perceptions[-1]
                signals = latest.get("signals", {})
                user_id = signals.get("user_id", "anonymous")
        except Exception:
            pass

        metadata = {
            "user_id": user_id,
            "task_type": "planning"
        }

        # Use reasoning-optimized model (GPT-4)
        response = await self.llm_router.generate(
            prompt=prompt,
            task_type=TaskType.REASONING,
            temperature=temperature,
            metadata=metadata,
        )
        
        # Parse response into structured plan
        steps = self._parse_plan_from_response(response.content, max_steps)
        
        # Calculate confidence
        confidence = self._calculate_confidence(response.content, steps)
        
        plan = ReasoningPlan(
            goal=goal,
            steps=steps,
            reasoning=response.content,
            confidence=confidence,
        )
        
        logger.info(f"Generated plan with {len(steps)} steps, confidence: {confidence:.2f}")

        # Self-Reflection: Review the plan
        plan = await self.review_plan(plan)

        return plan

    async def review_plan(self, plan: ReasoningPlan) -> ReasoningPlan:
        """
        Review the plan for errors and self-correct (Self-Reflection).
        """
        review_prompt = f"""Review the following security plan for potential issues.

GOAL: {plan.goal}

PLAN:
{plan.reasoning}

Identify:
1. Logical gaps or missing steps.
2. Dangerous commands or high risks without mitigation.
3. Unclear instructions.

If the plan is good, reply with "APPROVED".
If there are issues, reply with "ISSUES FOUND:" followed by the critique.
"""
        response = await self.llm_router.generate(
            prompt=review_prompt,
            task_type=TaskType.REASONING,
            temperature=0.3
        )

        if "ISSUES FOUND" in response.content:
            logger.info("Plan review found issues, self-correcting...")
            return await self.self_correct(plan, response.content)
        
        return plan
    
    def _parse_plan_from_response(
        self,
        response: str,
        max_steps: int
    ) -> List[ReasoningStep]:
        """Parse LLM response into structured steps."""
        steps = []
        
        # Simple parsing - in production, use more robust parsing or JSON mode
        lines = response.split('\n')
        current_step_num = 1
        
        for line in lines:
            line = line.strip()
            
            # Look for numbered steps
            if line and (line[0].isdigit() or line.startswith('Step')):
                # Extract step information
                description = line
                
                # Determine action type from keywords
                action_type = "analyze"  # default
                if any(word in line.lower() for word in ["scan", "check", "detect"]):
                    action_type = "scan"
                elif any(word in line.lower() for word in ["fix", "remediate", "patch"]):
                    action_type = "fix"
                elif any(word in line.lower() for word in ["report", "notify", "alert"]):
                    action_type = "report"
                elif any(word in line.lower() for word in ["configure", "setup", "deploy"]):
                    action_type = "configure"
                
                # Determine risk level
                risk_level = "low"
                if any(word in line.lower() for word in ["delete", "remove", "drop", "destroy"]):
                    risk_level = "high"
                elif any(word in line.lower() for word in ["modify", "update", "change", "deploy"]):
                    risk_level = "medium"
                
                step = ReasoningStep(
                    step_number=current_step_num,
                    description=description,
                    action_type=action_type,
                    risk_level=risk_level,
                    parameters={},
                )
                
                steps.append(step)
                current_step_num += 1
                
                if len(steps) >= max_steps:
                    break
        
        # If no steps were parsed, create a generic one
        if not steps:
            steps.append(ReasoningStep(
                step_number=1,
                description="Analyze the situation and gather information",
                action_type="analyze",
                risk_level="low",
            ))
        
        return steps
    
    def _calculate_confidence(self, reasoning: str, steps: List[ReasoningStep]) -> float:
        """
        Calculate confidence score for the plan.
        
        Heuristic-based scoring:
        - More detailed reasoning = higher confidence
        - Clear steps = higher confidence
        - Uncertainty words = lower confidence
        """
        confidence = 0.5  # baseline
        
        # Bonus for detailed reasoning
        if len(reasoning) > 200:
            confidence += 0.2
        
        # Bonus for clear steps
        if len(steps) >= 2:
            confidence += 0.1
        
        # Penalty for uncertainty
        uncertainty_words = ["maybe", "might", "possibly", "uncertain", "unclear"]
        if any(word in reasoning.lower() for word in uncertainty_words):
            confidence -= 0.2
        
        # Bonus for specific actions
        if any(step.action_type in ["scan", "fix", "configure"] for step in steps):
            confidence += 0.1
        
        return max(0.0, min(1.0, confidence))  # Clamp to [0, 1]
    
    async def self_correct(
        self,
        plan: ReasoningPlan,
        feedback: str
    ) -> ReasoningPlan:
        """
        Self-correct a plan based on feedback.
        
        Args:
            plan: The original plan
            feedback: Feedback about what went wrong
            
        Returns:
            Corrected plan
        """
        prompt = f"""The following plan was attempted but encountered issues. Revise the plan to address the problems.

ORIGINAL GOAL: {plan.goal}

ORIGINAL PLAN:
{plan.reasoning}

FEEDBACK/ISSUES:
{feedback}

Generate a revised plan that addresses these issues. Be specific about what changes you're making and why.
"""
        
        response = await self.llm_router.generate(
            prompt=prompt,
            task_type=TaskType.REASONING,
            temperature=0.7,
        )
        
        # Parse revised plan
        revised_steps = self._parse_plan_from_response(response.content, len(plan.steps) + 2)
        
        revised_plan = ReasoningPlan(
            goal=plan.goal,
            steps=revised_steps,
            reasoning=response.content,
            confidence=self._calculate_confidence(response.content, revised_steps),
        )
        
        logger.info(f"Self-corrected plan: {len(revised_steps)} steps")
        
        return revised_plan
