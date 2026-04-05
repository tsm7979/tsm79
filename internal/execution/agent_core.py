# backend/src/core/agentic/agent_core.py

"""
Core agent architecture implementing the autonomous agent pattern.

Agents combine perception, reasoning, memory, and action systems into
a cohesive decision-making entity.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from router.orchestrator import PolyLLMOrchestrator as LLMRouter, TaskType
from .reasoning_loop import ReasoningLoop
from execution.memory_manager import MemoryManager
from .action_executor import ActionExecutor, Action
from .approval_gates import ApprovalGate
from learning.policies.learner import PolicyLearner
from learning.outcomes.engine import OutcomeIntelligenceEngine, FixSource

logger = logging.getLogger(__name__)


class AgentState(str, Enum):
    """Agent lifecycle states."""
    
    INITIALIZING = "initializing"
    IDLE = "idle"
    PERCEIVING = "perceiving"  # Collecting signals
    REASONING = "reasoning"  # Planning and decision making
    AWAITING_APPROVAL = "awaiting_approval"  # Waiting for human approval
    EXECUTING = "executing"  # Performing actions
    REFLECTING = "reflecting"  # Analyzing results
    ERROR = "error"
    TERMINATED = "terminated"


@dataclass
class AgentConfig:
    """Configuration for an agent."""
    
    name: str
    description: str
    capabilities: List[str] = field(default_factory=list)
    max_iterations: int = 10
    require_approval_for_high_risk: bool = True
    auto_reflect: bool = True
    memory_ttl_seconds: int = 3600  # 1 hour default
    reasoning_temperature: float = 0.7


class Agent:
    """
    Autonomous agent with perception, reasoning, memory, and action capabilities.
    
    The agent follows a continuous loop:
    1. Perceive: Collect signals from the environment
    2. Reason: Plan actions using LLM-powered reasoning
    3. Approve: Get human approval for high-risk actions (optional)
    4. Act: Execute approved actions
    5. Reflect: Analyze results and update beliefs
    6. Repeat
    """
    
    def __init__(
        self,
        config: AgentConfig,
        llm_router: Optional[LLMRouter] = None,
        memory_manager: Optional[MemoryManager] = None,
        action_executor: Optional[ActionExecutor] = None,
        approval_gate: Optional[ApprovalGate] = None,
    ):
        """
        Initialize agent.
        
        Args:
            config: Agent configuration
            llm_router: LLM router for reasoning (auto-created if None)
            memory_manager: Memory system (auto-created if None)
            action_executor: Action executor (auto-created if None)
            approval_gate: Approval gate (auto-created if None)
        """
        self.agent_id = str(uuid.uuid4())
        self.config = config
        
        # Core components
        self.llm_router = llm_router or LLMRouter()
        self.memory = memory_manager or MemoryManager(agent_id=self.agent_id)
        self.executor = action_executor or ActionExecutor()
        self.approval_gate = approval_gate or ApprovalGate()
        
        # Learning components
        self.policy_learner = PolicyLearner()
        self.outcome_engine = OutcomeIntelligenceEngine()
        
        # Reasoning loop
        self.reasoning_loop = ReasoningLoop(
            llm_router=self.llm_router,
            memory_manager=self.memory
        )
        
        # State management
        self.state = AgentState.INITIALIZING
        self.current_goal: Optional[str] = None
        self.iteration_count = 0
        self.created_at = datetime.utcnow()
        self.last_active = datetime.utcnow()
        
        # Execution history
        self.execution_history: List[Dict[str, Any]] = []
        
        logger.info(f"Agent initialized: {self.config.name} ({self.agent_id})")
    
    def set_goal(self, goal: str) -> None:
        """Set the agent's current goal."""
        self.current_goal = goal
        self.memory.store_goal(goal)
        logger.info(f"Agent {self.config.name} goal set: {goal}")
    
    async def perceive(self, signals: Dict[str, Any]) -> None:
        """
        Perceive signals from the environment.
        
        Args:
            signals: Dict of signal type -> signal data
        """
        self.state = AgentState.PERCEIVING
        self.last_active = datetime.utcnow()
        
        # Store signals in memory
        await self.memory.store_perception(signals)
        
        # LEARNING: Filter noise using PolicyLearner
        filtered_signals = {}
        for k, v in signals.items():
            # Basic suppression check - extend logic as needed for specific signal types
            should_process, _, _ = self.policy_learner.evaluate_signal(
                signal_type="perception",
                finding_type=k,
                source="environment"
            )
            if should_process:
                filtered_signals[k] = v
            else:
                logger.info(f"Signal suppressed by policy: {k}")
        
        if len(filtered_signals) < len(signals):
            logger.info(f"Filtered {len(signals) - len(filtered_signals)} noisy signals")
            # Update memory with refined view if needed, but for now just log
       
        logger.debug(f"Agent perceived {len(signals)} signals")
    
    async def reason(self) -> List[Action]:
        """
        Reason about the current situation and plan actions.
        
        Uses the reasoning loop to:
        - Understand the current state
        - Plan actions to achieve the goal
        - Evaluate potential outcomes
        
        Returns:
            List of planned actions
        """
        self.state = AgentState.REASONING
        self.last_active = datetime.utcnow()
        
        if not self.current_goal:
            logger.warning("No goal set for agent, cannot reason")
            return []
        
        # Get context from memory
        context = await self.memory.get_reasoning_context()
        
        # Generate plan using reasoning loop
        plan = await self.reasoning_loop.generate_plan(
            goal=self.current_goal,
            context=context,
            temperature=self.config.reasoning_temperature,
        )
        
        # Convert plan steps to actions
        actions = []
        for step in plan.steps:
            action = Action(
                action_type=step.action_type,
                description=step.description,
                parameters=step.parameters,
                risk_level=step.risk_level,
            )
            actions.append(action)
        
        # Store plan in memory
        await self.memory.store_plan(plan)
        
        logger.info(f"Agent planned {len(actions)} actions")
        return actions
    
    async def execute_actions(self, actions: List[Action]) -> List[Dict[str, Any]]:
        """
        Execute actions, with approval gates for high-risk actions.
        
        Args:
            actions: List of actions to execute
            
        Returns:
            List of execution results
        """
        results = []
        
        for i, action in enumerate(actions):
            # Check if approval is needed
            if action.risk_level == "high" and self.config.require_approval_for_high_risk:
                self.state = AgentState.AWAITING_APPROVAL
                
                # Request approval
                approved = await self.approval_gate.request_approval(
                    agent_id=self.agent_id,
                    action=action,
                    context={
                        "goal": self.current_goal,
                        "action_index": i,
                        "total_actions": len(actions),
                    }
                )
                
                if not approved:
                    logger.warning(f"Action {i+1} rejected by approval gate")
                    results.append({
                        "action": action.to_dict(),
                        "status": "rejected",
                        "message": "Rejected by approval gate",
                    })
                    continue
            
            # Execute action
            self.state = AgentState.EXECUTING
            self.last_active = datetime.utcnow()
            
            try:
                _t0 = time.monotonic()
                result = await self.executor.execute(action)
                results.append({
                    "action": action.to_dict(),
                    "status": "success",
                    "result": result.to_dict(),
                    "time_taken": time.monotonic() - _t0,
                })
                
                # Store result in memory
                await self.memory.store_action_result(action, result)
                
            except Exception as e:
                logger.error(f"Action execution failed: {e}")
                results.append({
                    "action": action.to_dict(),
                    "status": "error",
                    "error": str(e),
                })
        
        return results
    
    async def reflect(self, results: List[Dict[str, Any]], signals: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Reflect on action results and update beliefs.
        
        Args:
            results: List of execution results
            signals: Original signals that triggered this iteration (optional)
            
        Returns:
            Reflection summary
        """
        self.state = AgentState.REFLECTING
        self.last_active = datetime.utcnow()
        
        # Extract context from signals for enhanced responses
        rag_results = signals.get("rag_results", []) if signals else []
        structured_context = signals.get("structured_context", {}) if signals else {}
        intent_type = signals.get("intent_type", "GENERAL") if signals else "GENERAL"
        user_message = signals.get("content", "") if signals else ""

        # Format RAG context (FULL CONTENT, no truncation)
        knowledge_context = ""
        if rag_results:
            knowledge_context = "RETRIEVED KNOWLEDGE:\n\n"
            for i, res in enumerate(rag_results, 1):
                content = res.get("content", "")
                filename = res.get("metadata", {}).get("filename", f"Document {i}")
                knowledge_context += f"[{i}] From {filename}:\n{content}\n\n"

        # Build context-aware prompt based on intent
        if intent_type in ["QUESTION", "QUERY", "GENERAL"] and len(results) == 0:
            # Simple Q&A - focus on answering directly
            reflection_prompt = f"""You are TSM99, an AI security analyst assistant.

User asked: "{user_message}"

{knowledge_context if knowledge_context else "No uploaded data available yet. Inform the user they need to upload relevant files first."}

Provide a helpful, accurate response based on the available knowledge.
If knowledge is available, cite specific details from the documents.
If no knowledge is available, politely inform the user they need to upload relevant files.

Keep your response concise but informative (2-4 sentences).

RESPONSE: """
        else:
            # Action-based workflow - analyze results
            reflection_prompt = f"""Goal: {self.current_goal}

User Intent: {intent_type}
User Message: "{user_message}"

{knowledge_context}

Actions Executed:
{results}

Analyze the results and provide a comprehensive response to the user:
1. What was accomplished?
2. Were there any issues or errors?
3. What are the key findings?
4. What should the user do next (if applicable)?

Provide a clear, actionable response summarizing the outcome.

RESPONSE: """
        
        response = await self.llm_router.generate(
            prompt=reflection_prompt,
            task_type=TaskType.REASONING,
        )
        
        # Parse output for user response
        content = response.content
        user_response = ""
        if "RESPONSE:" in content:
            parts = content.split("RESPONSE:")
            if len(parts) > 1:
                user_response = parts[1].strip()
        else:
            # Fallback to the whole analysis if no specific tag
            user_response = content
        
        reflection = {
            "timestamp": datetime.utcnow().isoformat(),
            "results_analyzed": len(results),
            "analysis": content,
            "goal_achieved": "achieved" in content.lower(),  # Simple heuristic
            "user_response": user_response
        }
        
        # Store reflection
        await self.memory.store_reflection(reflection)
        
        # LEARNING: Record outcomes
        for result in results:
            action = result.get("action", {})
            status = result.get("status", "")
            
            # Extract elapsed time recorded during execution
            time_taken = result.get("time_taken", 0.0)
            
            self.outcome_engine.record_outcome(
                finding_id=self.current_goal or "general_task",
                finding_type=action.get("action_type", "unknown"),
                fix_source=FixSource.POLY_LLM, # Assume LLM generated this plan
                verification_status="pass" if status == "success" else "fail",
                execution_context={"agent_id": self.agent_id},
                time_to_fix_seconds=time_taken
            )
        
        return reflection
    
    async def run_iteration(self, signals: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run one iteration of the agent loop.
        
        Args:
            signals: Environment signals to process
            
        Returns:
            Iteration summary
        """
        iteration_start = datetime.utcnow()
        self.iteration_count += 1
        
        logger.info(f"Agent iteration {self.iteration_count} starting")
        
        # Perceive
        await self.perceive(signals)
        
        # Reason
        actions = await self.reason()
        
        # Execute
        results = await self.execute_actions(actions)
        
        # Reflect
        reflection = await self.reflect(results, signals=signals)
        
        # Build summary
        iteration_summary = {
            "iteration": self.iteration_count,
            "duration_ms": (datetime.utcnow() - iteration_start).total_seconds() * 1000,
            "signals_perceived": len(signals),
            "actions_planned": len(actions),
            "actions_executed": sum(1 for r in results if r["status"] == "success"),
            "goal_achieved": reflection.get("goal_achieved", False),
            "state": self.state.value,
            "response": reflection.get("user_response", "")
        }
        
        self.execution_history.append(iteration_summary)
        
        # Check if we should continue
        if reflection.get("goal_achieved") or self.iteration_count >= self.config.max_iterations:
            self.state = AgentState.IDLE
            logger.info(f"Agent completing after {self.iteration_count} iterations")
        
        return iteration_summary
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            "agent_id": self.agent_id,
            "name": self.config.name,
            "state": self.state.value,
            "current_goal": self.current_goal,
            "iterations": self.iteration_count,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "capabilities": self.config.capabilities,
            "execution_history": self.execution_history[-10:],  # Last 10
        }
