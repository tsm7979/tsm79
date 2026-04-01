#!/usr/bin/env python3
"""
TSM Layer CLI
=============

AI Firewall + Routing for every LLM call.

Usage:
    tsm run "your prompt"
    tsm audit <trace_id>
    tsm config
"""

import sys
import os
import time
import json
import asyncio
from datetime import datetime
from typing import Optional
import argparse

# Color codes for terminal output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'

    # Status colors
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    PURPLE = '\033[95m'
    GRAY = '\033[90m'

    # Background
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_RED = '\033[41m'


def print_banner():
    """Print TSM banner."""
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 50)
    print("              TSM LAYER                   ")
    print("     AI Firewall + Routing Active        ")
    print("=" * 50)
    print(Colors.RESET)
    print()


def print_section(title: str, icon: str = ""):
    """Print section header."""
    print(f"{Colors.BOLD}{icon} {title}{Colors.RESET}")
    print("-" * 50)


def print_success(message: str):
    """Print success message."""
    print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")


def print_warning(message: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")


def print_error(message: str):
    """Print error message."""
    print(f"{Colors.RED}[X] {message}{Colors.RESET}")


def print_info(message: str):
    """Print info message."""
    print(f"{Colors.BLUE}[i] {message}{Colors.RESET}")


def print_result(message: str):
    """Print result."""
    print(f"{Colors.WHITE}{message}{Colors.RESET}")


def simulate_typing_delay():
    """Simulate processing with slight delay for better UX."""
    time.sleep(0.2)


async def analyze_input(prompt: str) -> dict:
    """Analyze input for sensitive data."""
    simulate_typing_delay()

    # Check for common PII patterns
    sensitive_patterns = {
        'ssn': r'\d{3}-\d{2}-\d{4}',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    }

    detected = []
    import re
    for pattern_name, pattern in sensitive_patterns.items():
        if re.search(pattern, prompt, re.IGNORECASE):
            detected.append(pattern_name)

    # Check for personal identifiers
    if any(word in prompt.lower() for word in ['my name is', 'i am', "i'm"]):
        detected.append('personal_identity')

    return {
        'has_sensitive': len(detected) > 0,
        'detected_types': detected,
        'original': prompt
    }


async def sanitize_input(prompt: str, detected_types: list) -> str:
    """Sanitize sensitive data."""
    simulate_typing_delay()

    import re
    sanitized = prompt

    # Sanitize SSN
    if 'ssn' in detected_types:
        sanitized = re.sub(r'\d{3}-\d{2}-\d{4}', '[REDACTED_SSN]', sanitized)

    # Sanitize email
    if 'email' in detected_types:
        sanitized = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]', sanitized)

    # Sanitize phone
    if 'phone' in detected_types:
        sanitized = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[REDACTED_PHONE]', sanitized)

    # Sanitize credit card
    if 'credit_card' in detected_types:
        sanitized = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[REDACTED_CREDIT_CARD]', sanitized)

    # Sanitize personal identity
    if 'personal_identity' in detected_types:
        sanitized = re.sub(r'(my name is|i am|i\'m)\s+\w+', r'\1 [REDACTED]', sanitized, flags=re.IGNORECASE)

    return sanitized


async def route_request(has_sensitive: bool, prompt: str) -> dict:
    """Determine routing decision."""
    simulate_typing_delay()

    if has_sensitive:
        return {
            'model': 'local-llm',
            'reason': 'sensitive data detected - privacy enforced',
            'mode': 'fully private',
            'provider': 'local'
        }

    # Simple heuristic routing
    prompt_lower = prompt.lower()

    if any(word in prompt_lower for word in ['analyze', 'complex', 'explain', 'why']):
        return {
            'model': 'gpt-4',
            'reason': 'complex reasoning required',
            'mode': 'cloud (sanitized)',
            'provider': 'openai'
        }
    elif any(word in prompt_lower for word in ['code', 'function', 'debug']):
        return {
            'model': 'gpt-4-turbo',
            'reason': 'code analysis task',
            'mode': 'cloud (sanitized)',
            'provider': 'openai'
        }
    else:
        return {
            'model': 'gpt-3.5-turbo',
            'reason': 'simple query',
            'mode': 'cloud (sanitized)',
            'provider': 'openai'
        }


async def execute_request(prompt: str, routing: dict) -> str:
    """Execute the AI request (simulated for demo)."""
    simulate_typing_delay()

    # For demo purposes, return simulated response
    # In production, this would call the actual model

    if routing['provider'] == 'local':
        return "Analysis complete. [Processed locally for privacy]"
    else:
        return "Analysis complete. [Processed via cloud with sanitization]"


def save_audit_log(trace_id: str, data: dict):
    """Save audit log."""
    log_dir = os.path.expanduser('~/.tsm/logs')
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, f"{trace_id}.json")
    with open(log_file, 'w') as f:
        json.dump(data, f, indent=2, default=str)


async def run_command(prompt: str):
    """Execute TSM run command with beautiful UX."""
    print_banner()

    # 1. INPUT ANALYSIS
    print_section("INPUT ANALYSIS", "[SCAN]")
    analysis = await analyze_input(prompt)

    if analysis['has_sensitive']:
        print_warning(f"Sensitive data detected:")
        for dt in analysis['detected_types']:
            print(f"   - {dt.replace('_', ' ').title()}")
    else:
        print_success("No sensitive data detected")

    print()

    # 2. SANITIZATION (if needed)
    sanitized_prompt = prompt
    if analysis['has_sensitive']:
        print_section("SANITIZATION", "[CLEAN]")
        print(f"{Colors.GRAY}Original:{Colors.RESET}")
        print(f'"{prompt[:60]}..."' if len(prompt) > 60 else f'"{prompt}"')
        print()

        sanitized_prompt = await sanitize_input(prompt, analysis['detected_types'])

        print(f"{Colors.GREEN}Sanitized:{Colors.RESET}")
        print(f'"{sanitized_prompt[:60]}..."' if len(sanitized_prompt) > 60 else f'"{sanitized_prompt}"')
        print()

    # 3. ROUTING DECISION
    print_section("ROUTING DECISION", "[ROUTE]")
    routing = await route_request(analysis['has_sensitive'], sanitized_prompt)

    print_info(f"Model: {routing['model']}")
    print_info(f"Reason: {routing['reason']}")
    print_info(f"Mode: {routing['mode']}")
    print()

    # 4. EXECUTION
    print_section("EXECUTION", "[EXEC]")
    print(f"{Colors.CYAN}Processing request...{Colors.RESET}")

    result = await execute_request(sanitized_prompt, routing)
    print()

    # 5. RESULT
    print_section("RESULT", "[OUTPUT]")
    print_result(result)
    print()

    # 6. AUDIT
    print_section("AUDIT", "[LOG]")

    # Generate trace ID
    import hashlib
    trace_id = f"tsm_{hashlib.sha256(f'{prompt}{time.time()}'.encode()).hexdigest()[:8]}"

    # Save audit log
    audit_data = {
        'trace_id': trace_id,
        'timestamp': datetime.utcnow().isoformat(),
        'original_prompt': prompt,
        'sanitized_prompt': sanitized_prompt,
        'analysis': analysis,
        'routing': routing,
        'result': result
    }
    save_audit_log(trace_id, audit_data)

    print_info(f"Trace ID: {trace_id}")
    print_success("Full trace recorded")
    print_success("Replay available")
    print()

    # TIP
    print(f"{Colors.PURPLE}>> Tip: Use `tsm audit {trace_id}` to replay this request{Colors.RESET}")
    print()


def audit_command(trace_id: str):
    """Show audit log for a trace ID."""
    print_banner()

    log_file = os.path.expanduser(f'~/.tsm/logs/{trace_id}.json')

    if not os.path.exists(log_file):
        print_error(f"Trace ID not found: {trace_id}")
        return

    with open(log_file, 'r') as f:
        data = json.load(f)

    print_section("AUDIT LOG", "[LOG]")
    print()

    print(f"{Colors.BOLD}Trace ID:{Colors.RESET} {data['trace_id']}")
    print(f"{Colors.BOLD}Timestamp:{Colors.RESET} {data['timestamp']}")
    print()

    print(f"{Colors.BOLD}Original Prompt:{Colors.RESET}")
    print(f'"{data["original_prompt"]}"')
    print()

    if data['sanitized_prompt'] != data['original_prompt']:
        print(f"{Colors.BOLD}Sanitized Prompt:{Colors.RESET}")
        print(f'"{data["sanitized_prompt"]}"')
        print()

    print(f"{Colors.BOLD}Routing Decision:{Colors.RESET}")
    print(f"  Model: {data['routing']['model']}")
    print(f"  Reason: {data['routing']['reason']}")
    print(f"  Mode: {data['routing']['mode']}")
    print()

    print(f"{Colors.BOLD}Result:{Colors.RESET}")
    print(f'"{data["result"]}"')
    print()


def config_command():
    """Show configuration."""
    print_banner()

    print_section("CONFIGURATION", "[CONFIG]")
    print()

    # Check for API keys
    openai_key = os.getenv('TSM_OPENAI_API_KEY', 'Not set')
    anthropic_key = os.getenv('TSM_ANTHROPIC_API_KEY', 'Not set')

    print(f"{Colors.BOLD}API Keys:{Colors.RESET}")
    print(f"  OpenAI: {'+Set' if openai_key != 'Not set' else 'X Not set'}")
    print(f"  Anthropic: {'+Set' if anthropic_key != 'Not set' else 'X Not set'}")
    print()

    print(f"{Colors.BOLD}Configuration:{Colors.RESET}")
    print(f"  Log Directory: {os.path.expanduser('~/.tsm/logs')}")
    print()

    if openai_key == 'Not set':
        print(f"{Colors.YELLOW}>> Set your API key:{Colors.RESET}")
        print(f"   export TSM_OPENAI_API_KEY=your-key-here")
        print()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='TSM Layer - AI Firewall + Routing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tsm run "Analyze this contract"
  tsm run "My name is John, SSN 123-45-6789, help me"
  tsm audit tsm_9x21ab
  tsm config
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Run command
    run_parser = subparsers.add_parser('run', help='Run AI request through TSM layer')
    run_parser.add_argument('prompt', type=str, help='Your prompt')

    # Audit command
    audit_parser = subparsers.add_parser('audit', help='View audit log')
    audit_parser.add_argument('trace_id', type=str, help='Trace ID to view')

    # Config command
    config_parser = subparsers.add_parser('config', help='Show configuration')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == 'run':
        asyncio.run(run_command(args.prompt))
    elif args.command == 'audit':
        audit_command(args.trace_id)
    elif args.command == 'config':
        config_command()


if __name__ == '__main__':
    main()
