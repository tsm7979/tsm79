'use client';

import { useEffect, useState, useCallback } from 'react';
import { MetricsCard } from '../components/MetricsCard';
import { RiskGauge } from '../components/RiskGauge';
import { ConnectionStatus } from '../components/ConnectionStatus';
import { RecentRequestsTable, RecentRequest } from '../components/RecentRequestsTable';

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

const EMPTY: Metrics = {
  total: 0, blocked: 0, redacted: 0, routed_local: 0, clean: 0,
  avg_risk: 0, top_pii: {}, recent: [],
};

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
        <ConnectionStatus connected={connected} lastUpdate={lastUpdate} />
      </div>

      {/* Top stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px', marginBottom: '20px' }}>
        <MetricsCard label="Total"    value={metrics.total}        color="var(--text)"   />
        <MetricsCard label="Blocked"  value={metrics.blocked}      color="var(--red)"    />
        <MetricsCard label="Redacted" value={metrics.redacted}     color="var(--yellow)" />
        <MetricsCard label="Local"    value={metrics.routed_local} color="var(--blue)"   />
        <MetricsCard label="Clean"    value={metrics.clean}        color="var(--green)"  />
      </div>

      {/* Second row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 2fr', gap: '12px', marginBottom: '20px' }}>
        <RiskGauge score={metrics.avg_risk} />

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

      <RecentRequestsTable requests={metrics.recent} />

      {/* Footer */}
      <div style={{ textAlign: 'center', color: 'var(--muted)', fontSize: '11px', marginTop: '20px' }}>
        Proxy: {PROXY_URL} · Dashboard auto-refreshes every 1.5s
      </div>
    </div>
  );
}
