# Benchmarks

Reproducible latency measurement for the TSM inline detection path. One command, real numbers, your hardware.

## What gets measured

The latency TSM **adds** to a request by running its detection primitive:

```
PIIDetector().scan(text)  ->  ScanResult (findings + severity)
```

This is the number that matters for an inline AI firewall: *how much does the guard cost per request?* It is **added overhead**, single-threaded, on the machine you run it on.

## What does NOT get measured

- Upstream model latency (hundreds of ms; you don't control it; it dwarfs the guard).
- Network round-trip to the provider.
- The Rust dataplane. This benchmarks the **Python reference implementation** that ships and runs today. The Rust dataplane (`dataplane/`) targets far lower latency; those are design targets until its build is verified ([#36](https://github.com/tsm7979/tsm79/issues/36)) and benchmarked here too.

## Run it

```bash
python benchmark/bench.py                 # default 5,000 iterations/category
python benchmark/bench.py --iters 20000   # tighter percentiles
python benchmark/bench.py --out benchmark/RESULTS.md
```

Or: `./benchmark/run.sh`. Output prints to the terminal and writes [`RESULTS.md`](RESULTS.md).

## Methodology

- **Path:** `PIIDetector().scan(text)` -- nothing else in the timing loop.
- **Clock:** `time.perf_counter_ns()`.
- **Warm-up:** 300 iterations discarded (import, regex compile, cold cache excluded).
- **Percentiles:** nearest-rank over the full sample set (p50 / p90 / p99 / max).
- **Corpus:** four categories (clean, PII, secret, mixed) x short and ~1 KB sizes. Inline in `bench.py` so the methodology is auditable.
- **Concurrency:** single thread by design. Multiply by core count for a first-order throughput estimate.
- **Proof of work:** the severity column shows clean->none, pii/secret/mixed->critical. The path is not timing a no-op.

## Honesty

Numbers vary with hardware -- that's the point; run it on your own box. We do not publish a number we can't reproduce, and design targets (Rust dataplane, eBPF/XDP) are labelled as targets, not measurements, everywhere. `RESULTS.md` carries a machine fingerprint and UTC timestamp so any result is traceable to the box that produced it.
