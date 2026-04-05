#!/usr/bin/env python3
"""
TSM Layer - Quick Demo
======================

Shows both scenarios:
1. Normal query (no sensitive data)
2. Sensitive data query (PII detected, sanitized, routed to local)

Run: python demo.py
"""

import subprocess
import sys
import time

def run_demo():
    print("=" * 60)
    print("TSM LAYER - QUICK DEMO")
    print("=" * 60)
    print()
    print("This demo shows TSM in action with 2 scenarios:")
    print("1. Normal query → Routes to cloud API")
    print("2. Sensitive data → Detects PII, sanitizes, routes locally")
    print()
    input("Press ENTER to start demo 1 (normal query)...")
    print()

    # Demo 1: Normal query
    print("=" * 60)
    print("DEMO 1: Normal Query")
    print("=" * 60)
    print()
    subprocess.run([sys.executable, "cli_app.py", "run", "What is artificial intelligence?"])
    print()

    input("Press ENTER for demo 2 (sensitive data detection)...")
    print()

    # Demo 2: Sensitive data
    print("=" * 60)
    print("DEMO 2: Sensitive Data Detection")
    print("=" * 60)
    print()
    subprocess.run([sys.executable, "cli_app.py", "run", "My name is John Smith, SSN 123-45-6789, analyze this contract risk"])
    print()

    print("=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
    print()
    print("What you just saw:")
    print("- PII automatically detected (SSN, personal info)")
    print("- Data sanitized before processing")
    print("- Routed to local model (privacy enforced)")
    print("- Full audit trail created")
    print()
    print("Try it yourself:")
    print("  python cli_app.py run \"your prompt here\"")
    print()
    print("View audit log:")
    print("  python cli_app.py audit <trace_id>")
    print()

if __name__ == "__main__":
    run_demo()
