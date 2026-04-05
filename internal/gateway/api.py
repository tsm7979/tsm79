"""
TSM Layer - Main API Gateway
=============================

Universal entry point for all AI control plane operations.
"""

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import logging

from gateway.pipeline import RequestPipeline
from identity import get_current_context
from trust import AuditLogger

# Initialize logger
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="TSM Layer - AI Control Plane",
    description="Universal control layer for AI execution, governance, and trust",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize pipeline
pipeline = RequestPipeline()
audit_logger = AuditLogger()


# Request/Response Models
class AIRequest(BaseModel):
    """Standard AI request format"""
    input: str
    context: Optional[Dict[str, Any]] = None
    model_preference: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


class ToolRequest(BaseModel):
    """Tool execution request"""
    tool_name: str
    inputs: Dict[str, Any]
    options: Optional[Dict[str, Any]] = None


class WorkflowRequest(BaseModel):
    """Workflow execution request"""
    workflow_id: str
    inputs: Dict[str, Any]
    options: Optional[Dict[str, Any]] = None


class AIResponse(BaseModel):
    """Standard AI response format"""
    result: Any
    trace_id: str
    metadata: Dict[str, Any]


# Health check
@app.get("/health")
async def health_check():
    """System health check"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "layers": {
            "gateway": "✓",
            "firewall": "✓",
            "router": "✓",
            "execution": "✓",
            "trust": "✓"
        }
    }


# Main AI Proxy Endpoint
@app.post("/ai-proxy", response_model=AIResponse)
async def ai_proxy(
    request: AIRequest,
    context = Depends(get_current_context)
):
    """
    Universal AI request handler

    Pipeline:
    1. Identity → Extract user/org context
    2. Firewall → Sanitize & classify
    3. Policy → Check permissions
    4. Router → Select model/tool
    5. Execution → Run logic
    6. Trust → Log everything
    7. Return → Sanitized response

    Args:
        request: AI request with input and options
        context: User/org context (injected by auth middleware)

    Returns:
        AIResponse with result and trace_id
    """
    try:
        # Execute through pipeline
        result = await pipeline.execute(
            input_text=request.input,
            context=context,
            options=request.options or {}
        )

        return AIResponse(
            result=result["output"],
            trace_id=result["trace_id"],
            metadata=result["metadata"]
        )

    except Exception as e:
        logger.error(f"AI proxy error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Tool Execution
@app.post("/tool/execute")
async def execute_tool(
    request: ToolRequest,
    context = Depends(get_current_context)
):
    """
    Execute a registered tool

    Args:
        request: Tool execution request
        context: User/org context

    Returns:
        Tool execution result with audit trail
    """
    try:
        result = await pipeline.execute_tool(
            tool_name=request.tool_name,
            inputs=request.inputs,
            context=context,
            options=request.options or {}
        )

        return {
            "result": result["output"],
            "trace_id": result["trace_id"],
            "tool": request.tool_name,
            "status": "success"
        }

    except Exception as e:
        logger.error(f"Tool execution error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Workflow Execution
@app.post("/workflow/run")
async def run_workflow(
    request: WorkflowRequest,
    context = Depends(get_current_context)
):
    """
    Execute a multi-step workflow

    Args:
        request: Workflow execution request
        context: User/org context

    Returns:
        Workflow execution result
    """
    try:
        result = await pipeline.execute_workflow(
            workflow_id=request.workflow_id,
            inputs=request.inputs,
            context=context,
            options=request.options or {}
        )

        return {
            "result": result["output"],
            "trace_id": result["trace_id"],
            "workflow": request.workflow_id,
            "steps_completed": result.get("steps_completed", 0),
            "status": "success"
        }

    except Exception as e:
        logger.error(f"Workflow execution error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Audit Trail Retrieval
@app.get("/audit/{trace_id}")
async def get_audit_trail(
    trace_id: str,
    context = Depends(get_current_context)
):
    """
    Retrieve complete audit trail for a request

    Args:
        trace_id: Unique trace identifier
        context: User/org context (for access control)

    Returns:
        Complete audit trail with all transformations
    """
    try:
        audit_trail = await audit_logger.get_trace(trace_id, context)

        if not audit_trail:
            raise HTTPException(status_code=404, detail="Trace not found")

        return {
            "trace_id": trace_id,
            "audit_trail": audit_trail,
            "replayable": True
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audit retrieval error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Tool Registry
@app.get("/tools")
async def list_tools(
    category: Optional[str] = None,
    risk_tier: Optional[str] = None
):
    """
    List available tools

    Args:
        category: Filter by category (security, analysis, automation)
        risk_tier: Filter by risk tier (low, medium, high)

    Returns:
        List of available tools with metadata
    """
    from tools import tool_registry

    tools = await tool_registry.discover(
        category=category,
        risk_tier=risk_tier
    )

    return {
        "tools": [
            {
                "name": tool.name,
                "category": tool.category,
                "description": tool.description,
                "risk_tier": tool.risk_tier,
                "permissions": tool.permissions
            }
            for tool in tools
        ],
        "count": len(tools)
    }


# System Status
@app.get("/status")
async def system_status():
    """Detailed system status"""
    return {
        "version": "1.0.0",
        "status": "operational",
        "components": {
            "gateway": {"status": "healthy"},
            "firewall": {"status": "healthy"},
            "router": {"status": "healthy"},
            "execution": {"status": "healthy"},
            "trust": {"status": "healthy"},
            "simulation": {"status": "healthy"}
        },
        "metrics": {
            "requests_processed": await pipeline.get_request_count(),
            "tools_available": await pipeline.get_tool_count(),
            "uptime": "calculate_uptime()"
        }
    }


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc)
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
