"""
TSM Layer - Request Pipeline
============================

Orchestrates the flow of requests through all 12 layers.
This is the core execution path for every AI operation.
"""

import uuid
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RequestPipeline:
    """
    Main request pipeline that orchestrates all layers.

    Flow:
    1. Identity → User/org context
    2. Firewall → Sanitize & classify
    3. Policy → Permission check
    4. Router → Model/tool selection
    5. Execution → Run logic
    6. Trust → Audit log
    7. Response → Return result
    """

    def __init__(self):
        """Initialize pipeline with all layer dependencies"""
        self._initialize_layers()
        self.request_count = 0

    def _initialize_layers(self):
        """Lazy load all layer dependencies"""
        # These will import the actual implementations
        # For now, we'll use placeholder imports
        self.firewall = None
        self.policy = None
        self.router = None
        self.execution = None
        self.trust = None
        self.simulation = None
        self.memory = None

    async def execute(
        self,
        input_text: str,
        context: Dict[str, Any],
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Execute a complete AI request through all layers.

        Args:
            input_text: Raw user input
            context: User/org/session context
            options: Execution options

        Returns:
            Dict with output, trace_id, and metadata
        """
        # Generate trace ID
        trace_id = str(uuid.uuid4())
        start_time = datetime.utcnow()

        try:
            logger.info(f"[{trace_id}] Starting request pipeline")

            # LAYER 2: Firewall - Sanitize & Classify
            logger.debug(f"[{trace_id}] Layer 2: Firewall")
            sanitized_input, risk_classification = await self._firewall_layer(
                input_text, context
            )

            # LAYER 4: Policy - Check permissions
            logger.debug(f"[{trace_id}] Layer 4: Policy")
            policy_decision = await self._policy_layer(
                sanitized_input, risk_classification, context, options
            )

            if not policy_decision["allowed"]:
                raise PermissionError(policy_decision["reason"])

            # LAYER 5: Router - Select target (model/tool/workflow)
            logger.debug(f"[{trace_id}] Layer 5: Router")
            routing_decision = await self._router_layer(
                sanitized_input, risk_classification, context, options
            )

            # LAYER 11: Simulation (if risky)
            if risk_classification.tier.value if hasattr(risk_classification, "tier") else "low" in ["high", "critical"]:
                logger.debug(f"[{trace_id}] Layer 11: Simulation")
                simulation_result = await self._simulation_layer(
                    routing_decision, sanitized_input, context
                )
                # Check if pre-flight passed
                if not simulation_result.get("pre_flight_passed", True):
                    raise RuntimeError(f"Simulation failed: {simulation_result.get('reason', 'Unknown error')}")

            # LAYER 7: Execution - Run the actual logic
            logger.debug(f"[{trace_id}] Layer 7: Execution")
            execution_result = await self._execution_layer(
                routing_decision, sanitized_input, context, options
            )

            # LAYER 9: Memory - Store context if needed
            if options and options.get("remember"):
                logger.debug(f"[{trace_id}] Layer 9: Memory")
                await self._memory_layer(
                    input_text, execution_result, context
                )

            # LAYER 10: Trust - Log everything
            logger.debug(f"[{trace_id}] Layer 10: Trust")
            await self._trust_layer(
                trace_id=trace_id,
                input_text=input_text,
                sanitized_input=sanitized_input,
                risk_classification=risk_classification,
                policy_decision=policy_decision,
                routing_decision=routing_decision,
                execution_result=execution_result,
                context=context,
                start_time=start_time
            )

            # Increment counter
            self.request_count += 1

            # Return response
            return {
                "output": execution_result["output"],
                "trace_id": trace_id,
                "metadata": {
                    "risk_tier": risk_classification.tier.value if hasattr(risk_classification, "tier") else "low",
                    "model_used": routing_decision.get("target"),
                    "model_name": routing_decision.get("model"),
                    "task_type": routing_decision.get("task_type"),
                    "routing_reason": routing_decision.get("reason"),
                    "estimated_cost": routing_decision.get("estimated_cost", 0.0),
                    "execution_time_ms": (datetime.utcnow() - start_time).total_seconds() * 1000,
                    "sanitized": sanitized_input != input_text
                }
            }

        except Exception as e:
            logger.error(f"[{trace_id}] Pipeline error: {str(e)}")

            # Log failure
            await self._trust_layer(
                trace_id=trace_id,
                input_text=input_text,
                error=str(e),
                context=context,
                start_time=start_time
            )

            raise

    async def execute_tool(
        self,
        tool_name: str,
        inputs: Dict[str, Any],
        context: Dict[str, Any],
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Execute a specific tool.

        Args:
            tool_name: Name of the tool to execute
            inputs: Tool inputs
            context: User/org context
            options: Execution options

        Returns:
            Tool execution result
        """
        trace_id = str(uuid.uuid4())
        start_time = datetime.utcnow()

        try:
            logger.info(f"[{trace_id}] Executing tool: {tool_name}")

            # Import tool registry
            from tools import tool_registry

            # Get tool
            tool = await tool_registry.get_tool(tool_name)

            # Validate inputs
            await tool_registry.validate_inputs(tool, inputs)

            # Check policy
            policy_decision = await self._policy_layer(
                {"tool": tool_name, "inputs": inputs},
                {"tier": tool.risk_tier},
                context,
                options
            )

            if not policy_decision["allowed"]:
                raise PermissionError(policy_decision["reason"])

            # Execute tool
            result = await tool_registry.execute(
                tool_name=tool_name,
                inputs=inputs,
                context=context
            )

            # Log
            await self._trust_layer(
                trace_id=trace_id,
                tool_name=tool_name,
                inputs=inputs,
                result=result,
                context=context,
                start_time=start_time
            )

            return {
                "output": result,
                "trace_id": trace_id
            }

        except Exception as e:
            logger.error(f"[{trace_id}] Tool execution error: {str(e)}")
            raise

    async def execute_workflow(
        self,
        workflow_id: str,
        inputs: Dict[str, Any],
        context: Dict[str, Any],
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Execute a multi-step workflow.

        Args:
            workflow_id: Workflow identifier
            inputs: Workflow inputs
            context: User/org context
            options: Execution options

        Returns:
            Workflow execution result
        """
        trace_id = str(uuid.uuid4())
        start_time = datetime.utcnow()

        try:
            logger.info(f"[{trace_id}] Executing workflow: {workflow_id}")

            # Import workflow engine
            from execution import workflow_engine

            # Execute workflow
            result = await workflow_engine.execute(
                workflow_id=workflow_id,
                inputs=inputs,
                context=context,
                trace_id=trace_id
            )

            # Log
            await self._trust_layer(
                trace_id=trace_id,
                workflow_id=workflow_id,
                inputs=inputs,
                result=result,
                context=context,
                start_time=start_time
            )

            return {
                "output": result["output"],
                "trace_id": trace_id,
                "steps_completed": result.get("steps_completed", 0)
            }

        except Exception as e:
            logger.error(f"[{trace_id}] Workflow execution error: {str(e)}")
            raise

    # Layer implementations (will be replaced with actual imports)

    async def _firewall_layer(self, input_text: str, context: Dict) -> tuple:
        """Layer 3: Firewall - Sanitize and classify"""
        from firewall import sanitizer, classifier

        # Sanitize (sync function)
        result = sanitizer.sanitize(input_text)
        sanitized = result.sanitized_text

        # Classify (async function)
        risk = await classifier.classify(sanitized, context, result)

        return sanitized, risk

    async def _policy_layer(
        self,
        input_data: Any,
        risk: Dict,
        context: Dict,
        options: Dict = None
    ) -> Dict[str, Any]:
        """Layer 4: Policy - Check permissions"""
        # Placeholder - will import from policy module
        from policy import engine

        decision = await engine.check(input_data, risk, context, options)
        return decision

    async def _router_layer(
        self,
        input_data: str,
        risk: Dict,
        context: Dict,
        options: Dict
    ) -> Dict[str, Any]:
        """Layer 5: Router - Select model/tool"""
        # Placeholder - will import from router module
        from router import decision_engine

        decision = await decision_engine.select(input_data, risk, context, options)
        return decision

    async def _execution_layer(
        self,
        routing_decision: Dict,
        input_data: str,
        context: Dict,
        options: Dict
    ) -> Dict[str, Any]:
        """Layer 7: Execution - Run logic"""
        # Placeholder - will import from execution module
        from execution import engine

        result = await engine.execute(routing_decision, input_data, context, options)
        return result

    async def _simulation_layer(
        self,
        routing_decision: Dict,
        input_data: str,
        context: Dict
    ) -> Dict[str, Any]:
        """Layer 11: Simulation - Pre-flight check"""
        # For v1, skip simulation layer (enterprise feature)
        # In production, this would run pre-flight validation
        return {
            "simulated": False,
            "pre_flight_passed": True,
            "warnings": []
        }

    async def _memory_layer(
        self,
        input_text: str,
        result: Dict,
        context: Dict
    ):
        """Layer 9: Memory - Store context"""
        # Placeholder - will import from memory module
        from memory import context_manager

        await context_manager.store(input_text, result, context)

    async def _trust_layer(self, **kwargs):
        """Layer 10: Trust - Immutable audit log"""
        # Placeholder - will import from trust module
        from trust import audit_logger

        await audit_logger.log(**kwargs)

    # Utility methods

    async def get_request_count(self) -> int:
        """Get total requests processed"""
        return self.request_count

    async def get_tool_count(self) -> int:
        """Get number of available tools"""
        from tools import tool_registry
        tools = await tool_registry.discover()
        return len(tools)
