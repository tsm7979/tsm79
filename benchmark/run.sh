#!/usr/bin/env bash
# One-command benchmark runner. Measures TSM inline-detection added latency
# (PIIDetector.scan) for the Python reference implementation, writes RESULTS.md.
#
#   ./benchmark/run.sh
#   ITERS=20000 ./benchmark/run.sh
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
ITERS="${ITERS:-5000}"
PY="${PYTHON:-python}"
export PYTHONIOENCODING=utf-8
echo "TSM benchmark -- $("$PY" --version 2>&1)"
echo "repo: $REPO_ROOT"
echo
exec "$PY" benchmark/bench.py --iters "$ITERS" --out benchmark/RESULTS.md
