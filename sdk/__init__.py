"""
TSM Python SDK
==============
Drop-in protection for any function that calls an AI provider.

Usage:

    import tsm

    @tsm.protect
    def summarize(text: str) -> str:
        return openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": text}],
        ).choices[0].message.content

    # With custom options
    @tsm.protect(policy="strict", org_id="acme", on_block="raise")
    def analyze(prompt: str) -> str:
        ...

    # Context manager
    with tsm.scan(text) as result:
        if result.is_clean:
            call_api(result.redacted_text)

    # Direct scan
    result = tsm.scan_text("My SSN is 123-45-6789")
    print(result.risk_score, result.pii_types, result.action)
"""

from sdk.protect import protect, scan, scan_text, TSMResult, TSMBlockedError
from sdk.client import TSMClient

__all__ = ["protect", "scan", "scan_text", "TSMResult", "TSMBlockedError", "TSMClient"]
__version__ = "2.0.0"
