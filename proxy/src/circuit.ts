/**
 * Per-upstream circuit breaker.
 *
 * States:
 *   CLOSED  — normal operation, requests flow through
 *   OPEN    — upstream is failing, requests fail fast
 *   HALF    — probe request allowed; if it succeeds → CLOSED
 *
 * Config (env):
 *   TSM_CB_THRESHOLD   — consecutive failures before OPEN (default 5)
 *   TSM_CB_TIMEOUT_MS  — ms to wait in OPEN before probing (default 30000)
 */

type State = 'CLOSED' | 'OPEN' | 'HALF';

interface Breaker {
  state:      State;
  failures:   number;
  openedAt:   number;
}

const THRESHOLD  = parseInt(process.env.TSM_CB_THRESHOLD  ?? '5');
const TIMEOUT_MS = parseInt(process.env.TSM_CB_TIMEOUT_MS ?? '30000');

const breakers = new Map<string, Breaker>();

function get(upstream: string): Breaker {
  if (!breakers.has(upstream)) {
    breakers.set(upstream, { state: 'CLOSED', failures: 0, openedAt: 0 });
  }
  return breakers.get(upstream)!;
}

/** Returns true if a request is allowed through for this upstream. */
export function isAllowed(upstream: string): boolean {
  const b = get(upstream);
  if (b.state === 'CLOSED') return true;
  if (b.state === 'OPEN') {
    if (Date.now() - b.openedAt >= TIMEOUT_MS) {
      b.state = 'HALF';
      return true;   // probe
    }
    return false;    // fail fast
  }
  return true;       // HALF: allow probe
}

/** Record a successful upstream response. */
export function recordSuccess(upstream: string): void {
  const b = get(upstream);
  b.failures = 0;
  b.state    = 'CLOSED';
}

/** Record an upstream failure. Opens the breaker if threshold exceeded. */
export function recordFailure(upstream: string): void {
  const b = get(upstream);
  b.failures++;
  if (b.state === 'HALF' || b.failures >= THRESHOLD) {
    b.state    = 'OPEN';
    b.openedAt = Date.now();
  }
}

/** Breaker status for the /health and /metrics endpoints. */
export function breakerStatus(): Record<string, { state: State; failures: number }> {
  const out: Record<string, { state: State; failures: number }> = {};
  for (const [k, v] of breakers) {
    out[k] = { state: v.state, failures: v.failures };
  }
  return out;
}
