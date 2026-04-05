#!/usr/bin/env python3
"""
TSM Layer - THE ONLY ENTRY POINT YOU NEED

Usage:
    python tsm.py "analyze my code for SQL injection"
    python tsm.py "My SSN is 123-45-6789. What should I do?"

Or import:
    from tsm import protect
    result = protect("Your prompt here")
"""

import sys
import os
import asyncio

# Add to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gateway.pipeline import RequestPipeline


async def protect(user_input: str, user_id: str = "default") -> dict:
    """
    THE ONLY FUNCTION YOU NEED.

    Send any AI request through TSM Layer.
    It will:
    - Remove PII automatically
    - Block dangerous requests
    - Route to best model
    - Audit everything

    Args:
        user_input: What the user asked
        user_id: Who asked (for audit trail)

    Returns:
        {
            "safe_output": "AI response with PII removed",
            "was_sanitized": True/False,
            "risk_level": "low|medium|high|critical",
            "trace_id": "abc123..."
        }
    """
    pipeline = RequestPipeline()

    try:
        result = await pipeline.execute(
            input_text=user_input,
            context={"user_id": user_id},
            options={}
        )

        return {
            "safe_output": result["output"],
            "was_sanitized": result["metadata"]["sanitized"],
            "risk_level": result["metadata"]["risk_tier"],
            "trace_id": result["trace_id"],
            "model_used": result["metadata"]["model_used"]
        }

    except PermissionError as e:
        # Blocked due to policy
        return {
            "safe_output": None,
            "was_sanitized": True,
            "risk_level": "critical",
            "blocked": True,
            "reason": str(e),
            "trace_id": None
        }

    except Exception as e:
        return {
            "safe_output": None,
            "was_sanitized": False,
            "risk_level": "unknown",
            "error": str(e),
            "trace_id": None
        }


def cli():
    """Command-line interface"""
    if len(sys.argv) < 2:
        print("Usage: python tsm.py 'your prompt here'")
        print("\nExamples:")
        print('  python tsm.py "analyze this code"')
        print('  python tsm.py "My SSN is 123-45-6789"')
        sys.exit(1)

    user_input = " ".join(sys.argv[1:])

    print("TSM Layer - AI Privacy Control")
    print("=" * 60)
    print(f"Input: {user_input[:100]}...")
    print("")

    result = asyncio.run(protect(user_input))

    if result.get("blocked"):
        print("[BLOCKED]")
        print(f"Reason: {result['reason']}")
        print(f"Risk: {result['risk_level']}")
    else:
        print(f"[{result['risk_level'].upper()}]")
        print(f"Output: {result['safe_output']}")
        print(f"Sanitized: {result['was_sanitized']}")
        print(f"Model: {result['model_used']}")
        print(f"Trace: {result['trace_id']}")


if __name__ == "__main__":
    cli()
