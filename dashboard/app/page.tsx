'use client';

import { useEffect, useState, useCallback } from 'react';

const PROXY_URL = process.env.NEXT_PUBLIC_PROXY_URL ?? 'http://localhost:8080';

interface Metrics {
  total: number;
  blocked: number;
  redacted: number;
  routed_local: number;
  clean: number;
  avg_risk: number;
  top_pii: Record<string, number>;
  recent: RecentRequest[];
}

interface RecentRequest {
  id: string;
  ts: number;
  model: string;
  action: 'allow' | 'redact' | 'block' | 'route_local';
  pii_types: string[];
  risk_score: number;
  latency_ms: number;
  upstream: string;
}

const EMPTY: Metrics = {
  total: 0, blocked: 0, redacted: 0, routed_local: 0, clean: 0,
  avg_risk: 0, top_pii: {}, recent: [],
};

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

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics>(EMPTY);
  const [connected, setConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<string>('—');

  const fetchMetrics = useCallback(async () => {
    try {
      const res = await fetch(`${PROXY_URL}/metrics`, { cache: 'no-store' });
      if (!res.ok) throw new Error('not ok');
      const data: Metrics = await res.json();
      setMetrics(data);
      setConnected(true);
      setLastUpdate(new Date().toLocaleTimeString());
    } catch {
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    fetchMetrics();
    const id = setInterval(fetchMetrics, 1500);
    return () => clearInterval(id);
  }, [fetchMetrics]);

  const blockRate = metrics.total ? ((metrics.blocked / metrics.total) * 100).toFixed(1) : '0.0';
  const topPii = Object.entries(metrics.top_pii).sort((a, b) => b[1] - a[1]).slice(0, 6);

  return (
    <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: 700, color: '#7c6af5' }}>TSM</h1>
          <p style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '2px' }}>AI Firewall · Live Dashboard</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className={connected ? 'pulse' : ''} style={{
            width: '8px', height: '8px', borderRadius: '50%',
            background: connected ? 'var(--green)' : 'var(--red)', display: 'inline-block',
          }} />
          <span style={{ color: 'var(--muted)', fontSize: '11px' }}>
            {connected ? `Live · ${lastUpdate}` : 'Disconnected · Start proxy'}
          </span>
        </div>
      </div>

      {/* Top stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px', marginBottom: '20px' }}>
        {[
          { label: 'Total', value: metrics.total, color: 'var(--text)' },
          { label: 'Blocked', value: metrics.blocked, color: 'var(--red)' },
          { label: 'Redacted', value: metrics.redacted, color: 'var(--yellow)' },
          { label: 'Local', value: metrics.routed_local, color: 'var(--blue)' },
          { label: 'Clean', value: metrics.clean, color: 'var(--green)' },
        ].map(({ label, value, color }) => (
          <div key={label} className="card" style={{ textAlign: 'center' }}>
            <div className="stat-value" style={{ color }}>{value.toLocaleString()}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>

      {/* Second row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 2fr', gap: '12px', marginBottom: '20px' }}>
        <div className="card">
          <div className="stat-value" style={{ color: riskColor(metrics.avg_risk) }}>
            {metrics.avg_risk}
          </div>
          <div className="stat-label">Avg Risk Score</div>
          <div className="risk-bar" style={{ marginTop: '12px' }}>
            <div className="risk-fill" style={{ width: `${metrics.avg_risk}%`, background: riskColor(metrics.avg_risk) }} />
          </div>
        </div>

        <div className="card">
          <div className="stat-value" style={{ color: parseFloat(blockRate) > 20 ? 'var(--red)' : 'var(--yellow)' }}>
            {blockRate}%
          </div>
          <div className="stat-label">Block Rate</div>
        </div>

        <div className="card">
          <div style={{ color: 'var(--muted)', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            Top PII Types Detected
          </div>
          {topPii.length === 0 && (
            <span style={{ color: 'var(--muted)' }}>No PII detected yet</span>
          )}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {topPii.map(([type, count]) => (
              <span key={type} style={{
                padding: '3px 10px', borderRadius: '4px', fontSize: '11px', fontWeight: 600,
                background: 'var(--border)', color: 'var(--text)',
              }}>
                {type} <span style={{ color: 'var(--muted)' }}>×{count}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Recent requests */}
      <div className="card">
        <div style={{ color: 'var(--muted)', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '14px' }}>
          Recent Requests
        </div>
        {metrics.recent.length === 0 ? (
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
              {metrics.recent.map((r) => (
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

      {/* Footer */}
      <div style={{ textAlign: 'center', color: 'var(--muted)', fontSize: '11px', marginTop: '20px' }}>
        Proxy: {PROXY_URL} · Dashboard auto-refreshes every 1.5s
      </div>
    </div>
  );
}
