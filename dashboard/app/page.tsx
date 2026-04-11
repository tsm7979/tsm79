'use client';

import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
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
  window_size?: number;
}

const EMPTY: Metrics = {
  total: 0, blocked: 0, redacted: 0, routed_local: 0, clean: 0,
  avg_risk: 0, top_pii: {}, recent: [],
};

type ActionFilter = 'all' | 'block' | 'redact' | 'route_local' | 'allow';

export default function Dashboard() {
  const [metrics, setMetrics]     = useState<Metrics>(EMPTY);
  const [connected, setConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<string>('—');
  const [filter, setFilter]       = useState<ActionFilter>('all');
  const [search, setSearch]       = useState('');
  const esRef = useRef<EventSource | null>(null);

  // ── SSE streaming — subscribe to live proxy events ──────────────────────
  const connect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
    }
    const es = new EventSource(`${PROXY_URL}/metrics/stream`);
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const data: Metrics = JSON.parse(e.data);
        setMetrics(data);
        setConnected(true);
        setLastUpdate(new Date().toLocaleTimeString());
      } catch { /* ignore parse errors */ }
    };

    es.onerror = () => {
      setConnected(false);
      es.close();
      esRef.current = null;
      // Reconnect after 3s
      setTimeout(connect, 3000);
    };
  }, []);

  useEffect(() => {
    connect();
    return () => {
      esRef.current?.close();
      esRef.current = null;
    };
  }, [connect]);

  // ── Filtered request list ────────────────────────────────────────────────
  const filteredRequests = useMemo(() => {
    return metrics.recent.filter(r => {
      const matchAction = filter === 'all' || r.action === filter;
      const q = search.toLowerCase();
      const matchSearch = !q || r.model.toLowerCase().includes(q)
        || r.pii_types.some(t => t.toLowerCase().includes(q))
        || r.upstream.toLowerCase().includes(q);
      return matchAction && matchSearch;
    });
  }, [metrics.recent, filter, search]);

  // ── Derived stats ────────────────────────────────────────────────────────
  const window = metrics.window_size ?? metrics.total;
  const blockRate = window
    ? ((metrics.blocked / window) * 100).toFixed(1)
    : '0.0';
  const topPii = Object.entries(metrics.top_pii).sort((a, b) => b[1] - a[1]).slice(0, 6);

  // ── Export CSV ───────────────────────────────────────────────────────────
  const exportCSV = () => {
    const rows = [
      ['time', 'model', 'action', 'pii_types', 'risk_score', 'upstream', 'latency_ms'],
      ...filteredRequests.map(r => [
        new Date(r.ts).toISOString(),
        r.model, r.action,
        r.pii_types.join('|'),
        String(r.risk_score),
        r.upstream,
        String(Math.round(r.latency_ms)),
      ]),
    ].map(row => row.join(',')).join('\n');

    const blob = new Blob([rows], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `tsm-requests-${Date.now()}.csv`;
    a.click(); URL.revokeObjectURL(url);
  };

  return (
    <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '20px', fontWeight: 700, color: '#7c6af5' }}>TSM</h1>
          <p style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '2px' }}>
            AI Firewall · Live Dashboard
            {metrics.window_size !== undefined && (
              <span> · last {metrics.window_size} requests</span>
            )}
          </p>
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
              <span
                key={type}
                onClick={() => setSearch(type)}
                style={{
                  padding: '3px 10px', borderRadius: '4px', fontSize: '11px', fontWeight: 600,
                  background: 'var(--border)', color: 'var(--text)', cursor: 'pointer',
                }}
                title="Click to filter"
              >
                {type} <span style={{ color: 'var(--muted)' }}>×{count}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Search + filter toolbar */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Search model, PII type, upstream…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            flex: 1, minWidth: '180px', padding: '6px 12px', borderRadius: '6px',
            border: '1px solid var(--border)', background: 'var(--surface)',
            color: 'var(--text)', fontSize: '12px', outline: 'none',
          }}
        />
        {(['all', 'block', 'redact', 'route_local', 'allow'] as ActionFilter[]).map(a => (
          <button
            key={a}
            onClick={() => setFilter(a)}
            style={{
              padding: '5px 12px', borderRadius: '6px', fontSize: '11px', fontWeight: 600,
              cursor: 'pointer', border: '1px solid var(--border)',
              background: filter === a ? 'var(--accent, #7c6af5)' : 'var(--surface)',
              color: filter === a ? '#fff' : 'var(--text)',
            }}
          >
            {a === 'all' ? 'All' : a}
          </button>
        ))}
        <button
          onClick={exportCSV}
          title="Export filtered requests as CSV"
          style={{
            padding: '5px 12px', borderRadius: '6px', fontSize: '11px', fontWeight: 600,
            cursor: 'pointer', border: '1px solid var(--border)',
            background: 'var(--surface)', color: 'var(--text)',
          }}
        >
          ↓ CSV
        </button>
        {(filter !== 'all' || search) && (
          <button
            onClick={() => { setFilter('all'); setSearch(''); }}
            style={{
              padding: '5px 10px', borderRadius: '6px', fontSize: '11px',
              cursor: 'pointer', border: '1px solid var(--border)',
              background: 'transparent', color: 'var(--muted)',
            }}
          >
            ✕ Clear
          </button>
        )}
      </div>

      <RecentRequestsTable requests={filteredRequests} />

      {/* Footer */}
      <div style={{ textAlign: 'center', color: 'var(--muted)', fontSize: '11px', marginTop: '20px' }}>
        Proxy: {PROXY_URL} · Live via SSE · {filteredRequests.length} of {metrics.recent.length} shown
      </div>
    </div>
  );
}
