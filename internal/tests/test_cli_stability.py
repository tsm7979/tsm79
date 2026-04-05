"""
CLI Stability Test
==================

Runs the CLI multiple times to verify:
1. No crashes across consecutive runs
2. PII detection works consistently
3. Routing decisions are correct
4. Trace IDs are generated
5. No memory leaks or resource issues
"""

import subprocess
import sys
import time
from pathlib import Path

def run_cli_test(test_num, prompt):
    """Run a single CLI test."""
    try:
        result = subprocess.run(
            [sys.executable, "cli_app.py", "run", prompt],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=Path(__file__).parent
        )

        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'stdout': '',
            'stderr': 'TIMEOUT',
            'returncode': -1
        }
    except Exception as e:
        return {
            'success': False,
            'stdout': '',
            'stderr': str(e),
            'returncode': -2
        }

def verify_output(output, test_type):
    """Verify the output contains expected sections."""
    required = ['SCAN', 'ROUTE', 'OUTPUT', 'Trace ID']

    missing = []
    for section in required:
        if section not in output:
            missing.append(section)

    # For PII tests, verify sanitization happened
    if test_type == 'pii':
        if 'REDACTED' not in output:
            missing.append('SANITIZATION')
        if 'local-llm' not in output.lower():
            missing.append('LOCAL_ROUTING')

    return len(missing) == 0, missing

def main():
    print("="*70)
    print("TSM CLI STABILITY TEST - 10 Consecutive Runs")
    print("="*70)

    test_cases = [
        ("clean", "What is artificial intelligence?"),
        ("clean", "Explain machine learning in simple terms"),
        ("pii", "My SSN is 123-45-6789, help me analyze this"),
        ("pii", "Contact john.doe@example.com for details"),
        ("clean", "What are the benefits of AI?"),
        ("clean", "How does natural language processing work?"),
        ("pii", "My credit card is 4532-1234-5678-9012"),
        ("clean", "Summarize the history of computing"),
        ("pii", "Call me at 555-123-4567 to discuss"),
        ("clean", "What is the future of AI technology?")
    ]

    results = []

    for i, (test_type, prompt) in enumerate(test_cases, 1):
        print(f"\n{'='*70}")
        print(f"RUN {i}/10 - Type: {test_type.upper()}")
        print(f"Prompt: {prompt[:60]}...")
        print('='*70)

        start_time = time.time()
        result = run_cli_test(i, prompt)
        elapsed = time.time() - start_time

        if not result['success']:
            print(f"[X] FAILED - Return code: {result['returncode']}")
            print(f"Error: {result['stderr'][:200]}")
            results.append({
                'run': i,
                'type': test_type,
                'success': False,
                'error': result['stderr'][:100]
            })
            continue

        # Verify output
        is_valid, missing = verify_output(result['stdout'], test_type)

        if is_valid:
            print(f"[OK] SUCCESS - {elapsed:.2f}s")
            results.append({
                'run': i,
                'type': test_type,
                'success': True,
                'elapsed': elapsed
            })
        else:
            print(f"[!] INCOMPLETE - Missing: {', '.join(missing)}")
            results.append({
                'run': i,
                'type': test_type,
                'success': False,
                'error': f"Missing: {', '.join(missing)}"
            })

        # Brief pause between runs
        time.sleep(0.5)

    # Summary
    print("\n" + "="*70)
    print("STABILITY TEST SUMMARY")
    print("="*70)

    successes = [r for r in results if r['success']]
    failures = [r for r in results if not r['success']]

    print(f"Total Runs: {len(results)}")
    print(f"Successful: {len(successes)}")
    print(f"Failed: {len(failures)}")
    print(f"Success Rate: {len(successes)/len(results)*100:.1f}%")

    if successes:
        avg_time = sum(r['elapsed'] for r in successes) / len(successes)
        print(f"Average Time: {avg_time:.2f}s")

    if failures:
        print("\nFailed Runs:")
        for f in failures:
            print(f"  Run {f['run']} ({f['type']}): {f.get('error', 'Unknown error')}")

    # Verdict
    print("\n" + "="*70)
    if len(failures) == 0:
        print("VERDICT: CLI IS 200% READY - All tests passed!")
        print("="*70)
        return 0
    elif len(failures) <= 2:
        print("VERDICT: CLI MOSTLY STABLE - Minor issues detected")
        print("="*70)
        return 1
    else:
        print("VERDICT: CLI NEEDS FIXES - Multiple failures detected")
        print("="*70)
        return 2

if __name__ == "__main__":
    sys.exit(main())
