/**
 * Token-bucket rate limiter — per client IP, configurable req/min.
 * Zero dependencies, in-memory, GC'd automatically on expiry.
 */

interface Bucket {
  tokens:    number;
  lastRefill: number;  // ms timestamp
}

const buckets = new Map<string, Bucket>();
const WINDOW_MS   = 60_000;                                           // 1 minute
const MAX_PER_MIN = parseInt(process.env.TSM_RATE_LIMIT ?? '100');    // configurable

/** Returns true if the request should be allowed, false if rate-limited. */
export function checkRateLimit(clientIp: string): boolean {
  const now = Date.now();
  let b = buckets.get(clientIp);

  if (!b) {
    b = { tokens: MAX_PER_MIN - 1, lastRefill: now };
    buckets.set(clientIp, b);
    return true;
  }

  // Refill tokens proportional to elapsed time
  const elapsed = now - b.lastRefill;
  const refill  = Math.floor((elapsed / WINDOW_MS) * MAX_PER_MIN);
  if (refill > 0) {
    b.tokens    = Math.min(MAX_PER_MIN, b.tokens + refill);
    b.lastRefill = now;
  }

  if (b.tokens <= 0) return false;
  b.tokens--;
  return true;
}

/** Remaining tokens for a client (for Retry-After header). */
export function remaining(clientIp: string): number {
  return buckets.get(clientIp)?.tokens ?? MAX_PER_MIN;
}

// GC stale buckets every 5 minutes
setInterval(() => {
  const cutoff = Date.now() - WINDOW_MS * 5;
  for (const [ip, b] of buckets) {
    if (b.lastRefill < cutoff) buckets.delete(ip);
  }
}, 5 * 60_000).unref();
