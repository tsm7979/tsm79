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
  client_ip?: string;
}

function actionBadgeClass(action: string) {
  const map: Record<string, string> = {
    allow: 'badge badge-allow',
    redact: 'badge badge-redact',
    block: 'badge badge-block',
    route_local: 'badge badge-local',
  };
  return map[action] ?? 'badge badge-muted';
}

function actionSymbol(action: string) {
  const map: Record<string, string> = {
    allow: '✓',
    redact: '✂',
    block: '✕',
    route_local: '↩',
  };
  return map[action] ?? '';
}

function riskColor(score: number) {
  if (score >= 80) return '#ef4444';
  if (score >= 55) return '#f59e0b';
  if (score >= 30) return '#3b82f6';
  return '#10b981';
}

function fmtTs(unix: number) {
  return new Date(unix).toLocaleTimeString('en-US', { hour12: false });
}

interface RecentRequestsTableProps {
  requests: RecentRequest[];
}

export function RecentRequestsTable({ requests }: RecentRequestsTableProps) {
  return (
    <div className="card">
      <div className="section-title">Recent Requests</div>
      {requests.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">◎</div>
          <div className="empty-state-text">
            No requests yet — send traffic through the proxy to see it here
          </div>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                {['Time', 'Client IP', 'Model', 'Action', 'PII Detected', 'Risk', 'Upstream', 'Latency'].map(h => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {requests.map((r) => (
                <tr key={r.id}>
                  <td style={{ color: 'var(--muted)', fontSize: '11px' }}>
                    {fmtTs(r.ts)}
                  </td>
                  <td style={{ color: 'var(--text2)', fontSize: '11px', fontFamily: 'monospace' }}>
                    {r.client_ip ?? '—'}
                  </td>
                  <td style={{ maxWidth: '160px' }}>
                    <span className="truncate" style={{ display: 'block', maxWidth: '160px' }}>
                      {r.model}
                    </span>
                  </td>
                  <td>
                    <span className={actionBadgeClass(r.action)}>
                      <span>{actionSymbol(r.action)}</span>
                      {r.action}
                    </span>
                  </td>
                  <td>
                    {r.pii_types.length > 0 ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {r.pii_types.slice(0, 3).map(t => (
                          <span
                            key={t}
                            style={{
                              padding: '1px 6px',
                              borderRadius: '3px',
                              fontSize: '10px',
                              background: 'var(--yellow-bg)',
                              color: 'var(--yellow)',
                              border: '1px solid rgba(245,158,11,0.15)',
                            }}
                          >
                            {t}
                          </span>
                        ))}
                        {r.pii_types.length > 3 && (
                          <span style={{ color: 'var(--muted)', fontSize: '10px' }}>
                            +{r.pii_types.length - 3}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span style={{ color: 'var(--muted)' }}>—</span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span
                        style={{
                          color: riskColor(r.risk_score),
                          fontWeight: 700,
                          fontSize: '12px',
                          minWidth: '24px',
                        }}
                      >
                        {r.risk_score}
                      </span>
                      <div
                        style={{
                          width: '36px',
                          height: '3px',
                          borderRadius: '2px',
                          background: 'var(--border)',
                          overflow: 'hidden',
                        }}
                      >
                        <div
                          style={{
                            width: `${r.risk_score}%`,
                            height: '100%',
                            borderRadius: '2px',
                            background: riskColor(r.risk_score),
                            transition: 'width 0.3s ease',
                          }}
                        />
                      </div>
                    </div>
                  </td>
                  <td style={{ color: 'var(--text2)', fontSize: '11px' }}>
                    {r.upstream}
                  </td>
                  <td style={{ color: 'var(--muted)', fontSize: '11px', textAlign: 'right' }}>
                    {Math.round(r.latency_ms)}
                    <span style={{ fontSize: '9px', marginLeft: '2px' }}>ms</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
