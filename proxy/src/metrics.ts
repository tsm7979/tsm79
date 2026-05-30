import { RequestStats } from './types.js';

/** In-memory ring buffer — last 1000 requests */
const RING_SIZE = 1000;
const ring: RequestStats[] = [];
let head = 0;

export function record(stat: RequestStats): void {
  ring[head % RING_SIZE] = stat;
  head++;
}

export function snapshot(): {
  total: number;
  blocked: number;
  redacted: number;
  routed_local: number;
  clean: number;
  avg_risk: number;
  top_pii: Record<string, number>;
  recent: RequestStats[];
  window_size: number;
} {
  const entries = ring.filter(Boolean);
  const blocked      = entries.filter(e => e.action === 'block').length;
  const redacted     = entries.filter(e => e.action === 'redact').length;
  const local        = entries.filter(e => e.action === 'route_local').length;
  const clean        = entries.filter(e => e.action === 'allow').length;
  const avg_risk     = entries.length
    ? entries.reduce((s, e) => s + e.risk_score, 0) / entries.length
    : 0;

  const top_pii: Record<string, number> = {};
  for (const e of entries) {
    for (const t of e.pii_types) {
      top_pii[t] = (top_pii[t] ?? 0) + 1;
    }
  }

  return {
    // total = absolute request count (lifetime); action counts reflect last RING_SIZE window
    total: head,
    blocked, redacted, routed_local: local, clean,
    avg_risk: Math.round(avg_risk * 10) / 10,
    top_pii,
    recent: entries.slice(-20).reverse(),
    // window_size lets the dashboard show "last N requests" correctly
    window_size: entries.length,
  };
}
