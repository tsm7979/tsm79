'use client';

export interface RecentRequest {
  id: string;
  ts: number;
  model: string;
  action: 'allow' | 'redact' | 'block' | 'route_local';
  pii_types: string[];
  risk_score: number;
  latency_ms: number;
  upstream: string;
}

function actionBadge(action: string) {
  const map: Record<string, string> = {
    allow: 'badge badge-allow',
    redact: 'badge badge-redact',
    block: 'badge badge-block',
    route_local: 'badge badge-local',
  };
  return map[action] ?? 'badge';
}

function riskColor(score: number) {
  if (score >= 80) return '#ef4444';
  if (score >= 55) return '#f59e0b';
  if (score >= 30) return '#3b82f6';
  return '#22c55e';
}

function ts(unix: number) {
  return new Date(unix).toLocaleTimeString('en-US', { hour12: false });
}

interface RecentRequestsTableProps {
  requests: RecentRequest[];
}

export function RecentRequestsTable({ requests }: RecentRequestsTableProps) {
  return (
    <div className="card">
      <div style={{ color: 'var(--muted)', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '14px' }}>
        Recent Requests
      </div>
      {requests.length === 0 ? (
        <div style={{ color: 'var(--muted)', textAlign: 'center', padding: '32px' }}>
          No requests yet · Send traffic through the proxy to see it here
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ color: 'var(--muted)', fontSize: '11px' }}>
              {['Time', 'Model', 'Action', 'PII', 'Risk', 'Upstream', 'Latency'].map(h => (
                <th key={h} style={{ textAlign: 'left', padding: '0 8px 8px', fontWeight: 500 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {requests.map((r) => (
              <tr key={r.id} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: '8px', color: 'var(--muted)' }}>{ts(r.ts)}</td>
                <td style={{ padding: '8px' }}>{r.model}</td>
                <td style={{ padding: '8px' }}>
                  <span className={actionBadge(r.action)}>{r.action}</span>
                </td>
                <td style={{ padding: '8px', color: r.pii_types.length ? 'var(--yellow)' : 'var(--muted)' }}>
                  {r.pii_types.join(', ') || '—'}
                </td>
                <td style={{ padding: '8px' }}>
                  <span style={{ color: riskColor(r.risk_score), fontWeight: 600 }}>{r.risk_score}</span>
                </td>
                <td style={{ padding: '8px', color: 'var(--muted)' }}>{r.upstream}</td>
                <td style={{ padding: '8px', color: 'var(--muted)' }}>{Math.round(r.latency_ms)}ms</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
