'use client';

import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { MetricsCard } from '../components/MetricsCard';
import { RiskGauge } from '../components/RiskGauge';
import { ConnectionStatus } from '../components/ConnectionStatus';
import { RecentRequestsTable, RecentRequest } from '../components/RecentRequestsTable';
import { ThreatIntelTab } from '../components/ThreatIntelTab';
import { ClusterTab } from '../components/ClusterTab';
import { PolicyTab } from '../components/PolicyTab';
import { AuditTab } from '../components/AuditTab';

const PROXY_URL = process.env.NEXT_PUBLIC_PROXY_URL ?? 'http://localhost:8080';

// ── Types ────────────────────────────────────────────────────────────────────

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

// Rolling history — 60 data points per metric
const HISTORY_LEN = 60;

type ActionFilter = 'all' | 'block' | 'redact' | 'route_local' | 'allow';
type Tab = 'overview' | 'threat-intel' | 'cluster' | 'policy' | 'audit';

// ── Tab definitions ───────────────────────────────────────────────────────────

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: 'overview',     label: 'Overview',     icon: '⬡' },
  { id: 'threat-intel', label: 'Threat Intel',  icon: '⚡' },
  { id: 'cluster',      label: 'Cluster',       icon: '◈' },
  { id: 'policy',       label: 'Policy',        icon: '◻' },
  { id: 'audit',        label: 'Audit Log',     icon: '▤' },
];

// ── Top blocked IPs helper (derived from recent requests) ─────────────────────

interface IpEntry { ip: string; count: number; }

function topBlockedIps(requests: RecentRequest[], n = 5): IpEntry[] {
  const counts: Record<string, number> = {};
  for (const r of requests) {
    if (r.action === 'block' && r.client_ip) {
      counts[r.client_ip] = (counts[r.client_ip] ?? 0) + 1;
    }
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([ip, count]) => ({ ip, count }));
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [metrics, setMetrics]       = useState<Metrics>(EMPTY);
  const [connected, setConnected]   = useState(false);
  const [lastUpdate, setLastUpdate] = useState<string>('—');
  const [filter, setFilter]         = useState<ActionFilter>('all');
  const [search, setSearch]         = useState('');
  const [activeTab, setActiveTab]   = useState<Tab>('overview');
  const esRef = useRef<EventSource | null>(null);

  // Rolling metric history
  const [histTotal,   setHistTotal]   = useState<number[]>([]);
  const [histBlocked, setHistBlocked] = useState<number[]>([]);
  const [histRedact,  setHistRedact]  = useState<number[]>([]);
  const [histLocal,   setHistLocal]   = useState<number[]>([]);
  const [histClean,   setHistClean]   = useState<number[]>([]);

  // Threat velocity (req/s)
  const totalTs = useRef<number[]>([]);
  const [velocity, setVelocity] = useState<number>(0);

  // ── Push to rolling history ───────────────────────────────────────────────
  function push(setter: React.Dispatch<React.SetStateAction<number[]>>, value: number) {
    setter(prev => {
      const next = [...prev, value];
      return next.length > HISTORY_LEN ? next.slice(next.length - HISTORY_LEN) : next;
    });
  }

  // ── SSE connection ────────────────────────────────────────────────────────
  const connect = useCallback(() => {
    esRef.current?.close();
    const es = new EventSource(`${PROXY_URL}/metrics/stream`);
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const data: Metrics = JSON.parse(e.data);
        setMetrics(data);
        setConnected(true);
        setLastUpdate(new Date().toLocaleTimeString('en-US', { hour12: false }));

        push(setHistTotal,   data.total);
        push(setHistBlocked, data.blocked);
        push(setHistRedact,  data.redacted);
        push(setHistLocal,   data.routed_local);
        push(setHistClean,   data.clean);

        // Compute velocity: track timestamps, measure rate over last 10s
        const now = Date.now();
        totalTs.current.push(now);
        const cutoff = now - 10_000;
        totalTs.current = totalTs.current.filter(t => t >= cutoff);
        const recentCount = totalTs.current.length;
        setVelocity(parseFloat((recentCount / 10).toFixed(2)));
      } catch { /* ignore */ }
    };

    es.onerror = () => {
      setConnected(false);
      es.close();
      esRef.current = null;
      setTimeout(connect, 3000);
    };
  }, []);

  useEffect(() => {
    connect();
    return () => { esRef.current?.close(); esRef.current = null; };
  }, [connect]);

  // ── Derived stats ─────────────────────────────────────────────────────────
  const windowSize = metrics.window_size ?? metrics.total;
  const blockRate = windowSize
    ? ((metrics.blocked / windowSize) * 100).toFixed(1)
    : '0.0';
  const topPii = Object.entries(metrics.top_pii).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const blockedIps = useMemo(() => topBlockedIps(metrics.recent), [metrics.recent]);

  // ── Filtered requests ─────────────────────────────────────────────────────
  const filteredRequests = useMemo(() => {
    return metrics.recent.filter(r => {
      const matchAction = filter === 'all' || r.action === filter;
      const q = search.toLowerCase();
      const matchSearch =
        !q ||
        r.model.toLowerCase().includes(q) ||
        r.pii_types.some(t => t.toLowerCase().includes(q)) ||
        r.upstream.toLowerCase().includes(q) ||
        (r.client_ip ?? '').toLowerCase().includes(q);
      return matchAction && matchSearch;
    });
  }, [metrics.recent, filter, search]);

  // ── Export CSV ────────────────────────────────────────────────────────────
  const exportCSV = () => {
    const rows = [
      ['time', 'client_ip', 'model', 'action', 'pii_types', 'risk_score', 'upstream', 'latency_ms'],
      ...filteredRequests.map(r => [
        new Date(r.ts).toISOString(),
        r.client_ip ?? '',
        r.model,
        r.action,
        r.pii_types.join('|'),
        String(r.risk_score),
        r.upstream,
        String(Math.round(r.latency_ms)),
      ]),
    ].map(row => row.join(',')).join('\n');

    const blob = new Blob([rows], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `tsm-audit-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'var(--bg)',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* ── Top bar ─────────────────────────────────────────────────────── */}
      <header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 100,
          background: 'rgba(10,14,26,0.95)',
          backdropFilter: 'blur(12px)',
          borderBottom: '1px solid var(--border)',
          padding: '0 24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: '52px',
        }}
      >
        {/* Logo + title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '30px',
                height: '30px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #7c6af5 0%, #4f46e5 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '14px',
                fontWeight: 800,
                color: '#fff',
                boxShadow: '0 0 12px rgba(124,106,245,0.4)',
              }}
            >
              T
            </div>
            <div>
              <div
                style={{
                  fontSize: '14px',
                  fontWeight: 800,
                  color: 'var(--text)',
                  letterSpacing: '0.05em',
                  lineHeight: 1,
                }}
              >
                TSM
                <span
                  style={{
                    fontSize: '9px',
                    fontWeight: 600,
                    color: 'var(--accent2)',
                    background: 'var(--accent-bg)',
                    border: '1px solid rgba(124,106,245,0.2)',
                    padding: '1px 6px',
                    borderRadius: '4px',
                    marginLeft: '8px',
                    verticalAlign: 'middle',
                  }}
                >
                  SOC
                </span>
              </div>
              <div style={{ fontSize: '9px', color: 'var(--muted)', marginTop: '2px', letterSpacing: '0.06em' }}>
                AI Firewall · Security Operations Center
              </div>
            </div>
          </div>

          {/* Velocity indicator */}
          <div
            style={{
              marginLeft: '16px',
              padding: '4px 12px',
              borderRadius: '20px',
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              fontSize: '11px',
              color: velocity > 5 ? 'var(--red)' : velocity > 1 ? 'var(--yellow)' : 'var(--muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: velocity > 5 ? 'var(--red)' : velocity > 1 ? 'var(--yellow)' : 'var(--muted)',
                display: 'inline-block',
              }}
            />
            <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>
              {velocity.toFixed(1)}
            </span>
            <span style={{ color: 'var(--muted)', fontSize: '9px' }}>req/s</span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {/* Block rate pill */}
          <div
            style={{
              padding: '4px 12px',
              borderRadius: '20px',
              background: parseFloat(blockRate) > 20 ? 'var(--red-bg)' : 'var(--surface)',
              border: `1px solid ${parseFloat(blockRate) > 20 ? 'rgba(239,68,68,0.25)' : 'var(--border)'}`,
              fontSize: '11px',
              color: parseFloat(blockRate) > 20 ? 'var(--red)' : 'var(--text2)',
              fontWeight: 600,
            }}
          >
            Block rate: {blockRate}%
          </div>

          {/* Window */}
          {windowSize > 0 && (
            <div style={{ fontSize: '10px', color: 'var(--muted)' }}>
              last {windowSize.toLocaleString()} req
            </div>
          )}

          <ConnectionStatus connected={connected} lastUpdate={lastUpdate} />
        </div>
      </header>

      {/* ── Tab navigation ──────────────────────────────────────────────── */}
      <nav
        style={{
          background: 'var(--bg2)',
          borderBottom: '1px solid var(--border)',
          padding: '0 24px',
        }}
      >
        <div className="tab-nav" style={{ borderBottom: 'none' }}>
          {TABS.map(tab => (
            <button
              key={tab.id}
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <span style={{ marginRight: '6px', opacity: 0.7 }}>{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>
      </nav>

      {/* ── Main content ─────────────────────────────────────────────────── */}
      <main style={{ flex: 1, padding: '24px', maxWidth: '1440px', width: '100%', margin: '0 auto' }}>

        {/* ── OVERVIEW TAB ───────────────────────────────────────────────── */}
        {activeTab === 'overview' && (
          <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

            {/* Metric cards with sparklines */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(5, 1fr)',
                gap: '12px',
              }}
            >
              <MetricsCard
                label="Total"
                value={metrics.total}
                color="var(--text)"
                history={histTotal}
                sub="All requests"
              />
              <MetricsCard
                label="Blocked"
                value={metrics.blocked}
                color="var(--red)"
                history={histBlocked}
                sub="Threat denied"
              />
              <MetricsCard
                label="Redacted"
                value={metrics.redacted}
                color="var(--yellow)"
                history={histRedact}
                sub="PII removed"
              />
              <MetricsCard
                label="Local"
                value={metrics.routed_local}
                color="var(--blue)"
                history={histLocal}
                sub="On-prem routed"
              />
              <MetricsCard
                label="Clean"
                value={metrics.clean}
                color="var(--green)"
                history={histClean}
                sub="No threats"
              />
            </div>

            {/* Second row: gauge + top IPs + PII breakdown */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '220px 1fr 1fr',
                gap: '12px',
              }}
            >
              {/* Radial risk gauge */}
              <RiskGauge score={metrics.avg_risk} />

              {/* Top blocked IPs */}
              <div className="card">
                <div className="section-title">Top Blocked IPs</div>
                {blockedIps.length === 0 ? (
                  <div style={{ color: 'var(--muted)', fontSize: '12px', padding: '12px 0' }}>
                    No blocked requests yet
                  </div>
                ) : (
                  <div>
                    {blockedIps.map((entry, i) => {
                      const maxCount = blockedIps[0].count;
                      return (
                        <div
                          key={entry.ip}
                          className="ip-rank-item"
                          style={{ cursor: 'pointer' }}
                          onClick={() => setSearch(entry.ip)}
                          title="Click to filter"
                        >
                          <div className="ip-rank-num">{i + 1}</div>
                          <div
                            style={{
                              fontFamily: 'monospace',
                              fontSize: '11px',
                              color: 'var(--red)',
                              fontWeight: 600,
                              minWidth: '110px',
                            }}
                          >
                            {entry.ip}
                          </div>
                          <div className="ip-rank-bar-bg">
                            <div
                              className="ip-rank-bar-fill"
                              style={{ width: `${(entry.count / maxCount) * 100}%` }}
                            />
                          </div>
                          <div
                            style={{
                              fontSize: '10px',
                              color: 'var(--muted)',
                              minWidth: '28px',
                              textAlign: 'right',
                            }}
                          >
                            ×{entry.count}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* PII type breakdown */}
              <div className="card">
                <div className="section-title">PII Detection Breakdown</div>
                {topPii.length === 0 ? (
                  <div style={{ color: 'var(--muted)', fontSize: '12px', padding: '12px 0' }}>
                    No PII detected yet
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {topPii.map(([type, count]) => {
                      const max = topPii[0][1];
                      return (
                        <div
                          key={type}
                          style={{ cursor: 'pointer' }}
                          onClick={() => setSearch(type)}
                          title="Click to filter"
                        >
                          <div
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              marginBottom: '3px',
                            }}
                          >
                            <span
                              style={{
                                fontSize: '11px',
                                fontWeight: 600,
                                color: 'var(--yellow)',
                              }}
                            >
                              {type}
                            </span>
                            <span style={{ fontSize: '10px', color: 'var(--muted)' }}>
                              {count.toLocaleString()}
                            </span>
                          </div>
                          <div
                            style={{
                              height: '3px',
                              borderRadius: '2px',
                              background: 'var(--border)',
                              overflow: 'hidden',
                            }}
                          >
                            <div
                              style={{
                                height: '100%',
                                width: `${(count / max) * 100}%`,
                                background: 'var(--yellow)',
                                opacity: 0.6,
                                borderRadius: '2px',
                                transition: 'width 0.4s ease',
                              }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Request filter toolbar */}
            <div
              style={{
                display: 'flex',
                gap: '8px',
                alignItems: 'center',
                flexWrap: 'wrap',
              }}
            >
              <input
                className="input"
                type="text"
                placeholder="Search model, PII type, IP, upstream…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                style={{ maxWidth: '300px', flex: '0 0 auto' }}
              />
              <div style={{ display: 'flex', gap: '4px' }}>
                {(['all', 'block', 'redact', 'route_local', 'allow'] as ActionFilter[]).map(a => (
                  <button
                    key={a}
                    className={`btn btn-sm ${filter === a ? 'btn-primary' : ''}`}
                    onClick={() => setFilter(a)}
                  >
                    {a === 'all' ? 'All' : a}
                  </button>
                ))}
              </div>
              {(filter !== 'all' || search) && (
                <button
                  className="btn btn-sm"
                  onClick={() => { setFilter('all'); setSearch(''); }}
                  style={{ color: 'var(--muted)' }}
                >
                  ✕ Clear
                </button>
              )}
              <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px', alignItems: 'center' }}>
                <span style={{ fontSize: '11px', color: 'var(--muted)' }}>
                  {filteredRequests.length} of {metrics.recent.length}
                </span>
                <button className="btn btn-sm" onClick={exportCSV}>
                  ↓ CSV
                </button>
              </div>
            </div>

            <RecentRequestsTable requests={filteredRequests} />

            {/* Footer */}
            <div
              style={{
                textAlign: 'center',
                color: 'var(--muted)',
                fontSize: '10px',
                padding: '8px 0',
                borderTop: '1px solid var(--border)',
              }}
            >
              Proxy: {PROXY_URL} · Live SSE stream ·{' '}
              {new Date().toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })}
            </div>
          </div>
        )}

        {/* ── THREAT INTEL TAB ──────────────────────────────────────────── */}
        {activeTab === 'threat-intel' && <ThreatIntelTab />}

        {/* ── CLUSTER TAB ───────────────────────────────────────────────── */}
        {activeTab === 'cluster' && <ClusterTab />}

        {/* ── POLICY TAB ────────────────────────────────────────────────── */}
        {activeTab === 'policy' && <PolicyTab />}

        {/* ── AUDIT LOG TAB ─────────────────────────────────────────────── */}
        {activeTab === 'audit' && <AuditTab />}
      </main>
    </div>
  );
}
