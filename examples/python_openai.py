"""
Example: Python + OpenAI SDK through TSM
=========================================
Zero code changes needed — just point OPENAI_BASE_URL at TSM.

Run:
    tsm start &
    eval "$(tsm enable --eval)"
    python examples/python_openai.py
"""

import os

# This is the ONLY change needed — everything else stays the same.
# TSM handles detection, redaction, routing, and audit logging.
os.environ.setdefault("OPENAI_BASE_URL", "http://localhost:8080")
os.environ.setdefault("OPENAI_API_KEY", "sk-dummy")  # TSM doesn't need a real key

try:
    from openai import OpenAI
    client = OpenAI()
except ImportError:
    print("openai not installed — showing mock output")
    print()
    print("With TSM active, these messages would be scanned before sending:")
    print("  'My SSN is 123-45-6789' → CRITICAL PII → routed to local model")
    print("  'What is 2 + 2?'        → clean        → routed to cloud")
    import sys; sys.exit(0)


def chat(message: str) -> str:
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": message}],
    )
    return response.choices[0].message.content


if __name__ == "__main__":
    test_cases = [
        "My SSN is 123-45-6789. Help me file taxes.",
        "My credit card is 4111 1111 1111 1111",
        "What is the capital of France?",
        "My email is alice@example.com — can you help me write a message?",
    ]

    print("\n🛡️  TSM Firewall Active — Python + OpenAI Demo\n")
    print("=" * 58)

    for msg in test_cases:
        print(f"\n→ Sending: {msg[:60]}...")
        reply = chat(msg)
        print(f"← Reply:  {reply[:200]}")
        print("-" * 58)
