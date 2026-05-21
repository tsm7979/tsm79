'use client';

import { useEffect, useState, useCallback } from 'react';

const ADMIN_URL = process.env.NEXT_PUBLIC_ADMIN_API_URL ?? 'http://localhost:9090';
const TOKEN = process.env.NEXT_PUBLIC_TSM_TOKEN ?? '';

// ── Types ────────────────────────────────────────────────────────────────────

interface ClusterNode {
  id: string;
  role?: string;
  addr?: string;
  region?: string;
  status: 'healthy' | 'unhealthy' | 'draining' | 'unknown';
  last_seen?: string;
  policy_version?: string | number;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function authHeaders() {
  return TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {};
}

function fmtRelTime(iso?: string) {
  if (!iso) return '—';
  try {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60_000) return `${Math.round(diff / 1000)}s ago`;
    if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
    return `${Math.round(diff / 3_600_000)}h ago`;
  } catch {
    return iso;
  }
}

function nodeCardClass(node: ClusterNode) {
  if (node.role === 'leader') return 'node-card leader';
  if (node.status === 'healthy') return 'node-card healthy';
  if (node.status === 'unhealthy') return 'node-card unhealthy';
  return 'node-card';
}

function statusDotClass(status: string) {
  if (status === 'healthy') return 'status-dot healthy';
  if (status === 'unhealthy') return 'status-dot unhealthy';
  if (status === 'draining') return 'status-dot warning';
  return 'status-dot unknown';
}

// ── Main component ───────────────────────────────────────────────────────────

export function ClusterTab() {
  const [nodes, setNodes] = useState<ClusterNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [drainingId, setDrainingId] = useState<string | null>(null);
  const [drainMsg, setDrainMsg] = useState<{ id: string; ok: boolean; text: string } | null>(null);

  // ── Fetch nodes (every 10s) ───────────────────────────────────────────────
  const fetchNodes = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch(`${ADMIN_URL}/api/nodes`, {
        headers: authHeaders(),
        cache: 'no-store',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: ClusterNode[] | { nodes: ClusterNode[] } = await res.json();
      setNodes(Array.isArray(data) ? data : data.nodes);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load cluster nodes');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchNodes();
    const id = setInterval(fetchNodes, 10_000);
    return () => clearInterval(id);
  }, [fetchNodes]);

  // ── Drain handler ─────────────────────────────────────────────────────────
  const handleDrain = async (nodeId: string) => {
    setDrainingId(nodeId);
    setDrainMsg(null);
    try {
      const res = await fetch(`${ADMIN_URL}/api/nodes/${encodeURIComponent(nodeId)}/drain`, {
        method: 'POST',
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setDrainMsg({ id: nodeId, ok: true, text: `Node ${nodeId} drain initiated` });
      setTimeout(fetchNodes, 1000);
    } catch (e) {
      setDrainMsg({ id: nodeId, ok: false, text: e instanceof Error ? e.message : 'Drain failed' });
    } finally {
      setDrainingId(null);
    }
  };

  // ── Derived stats ─────────────────────────────────────────────────────────
  const healthyCount = nodes.filter(n => n.status === 'healthy').length;
  const unhealthyCount = nodes.filter(n => n.status === 'unhealthy').length;
  const drainingCount = nodes.filter(n => n.status === 'draining').length;
  const healthPct = nodes.length > 0 ? (healthyCount / nodes.length) * 100 : 0;

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {error && (
        <div
          style={{
            padding: '10px 16px',
            borderRadius: '8px',
            background: 'var(--red-bg)',
            border: '1px solid rgba(239,68,68,0.25)',
            color: 'var(--red)',
            fontSize: '12px',
          }}
        >
          {error}
        </div>
      )}

      {/* Cluster health summary */}
      <div className="card-gradient-border">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '14px',
          }}
        >
          <div className="section-title" style={{ margin: 0 }}>Cluster Health</div>
          <div style={{ display: 'flex', gap: '16px' }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--green)' }}>
                {healthyCount}
              </div>
              <div className="stat-label">Healthy</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--red)' }}>
                {unhealthyCount}
              </div>
              <div className="stat-label">Unhealthy</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--yellow)' }}>
                {drainingCount}
              </div>
              <div className="stat-label">Draining</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text2)' }}>
                {nodes.length}
              </div>
              <div className="stat-label">Total</div>
            </div>
          </div>
          <button className="btn btn-sm" onClick={fetchNodes}>↻ Refresh</button>
        </div>

        {/* Health bar */}
        <div style={{ height: '6px', borderRadius: '3px', background: 'var(--border)', overflow: 'hidden' }}>
          <div
            style={{
              height: '100%',
              width: `${healthPct}%`,
              background:
                healthPct === 100
                  ? 'var(--green)'
                  : healthPct > 60
                  ? 'var(--yellow)'
                  : 'var(--red)',
              borderRadius: '3px',
              transition: 'width 0.5s ease',
            }}
          />
        </div>
        <div
          style={{
            fontSize: '10px',
            color: 'var(--muted)',
            marginTop: '6px',
            textAlign: 'right',
          }}
        >
          {healthPct.toFixed(0)}% healthy
        </div>
      </div>

      {/* Drain notification */}
      {drainMsg && (
        <div
          style={{
            padding: '10px 16px',
            borderRadius: '8px',
            background: drainMsg.ok ? 'var(--green-bg)' : 'var(--red-bg)',
            border: `1px solid ${drainMsg.ok ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
            color: drainMsg.ok ? 'var(--green)' : 'var(--red)',
            fontSize: '12px',
          }}
        >
          {drainMsg.text}
        </div>
      )}

      {/* Node grid */}
      {loading ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>
          {[1, 2, 3].map(i => (
            <div key={i} className="shimmer" style={{ height: '150px', borderRadius: '12px' }} />
          ))}
        </div>
      ) : nodes.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <div className="empty-state-icon">◎</div>
            <div className="empty-state-text">No nodes registered — start cluster nodes to see them here</div>
          </div>
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
            gap: '12px',
          }}
        >
          {nodes.map(node => (
            <div key={node.id} className={nodeCardClass(node)}>
              {/* Node header */}
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '12px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span className={statusDotClass(node.status)} />
                    <span style={{ fontWeight: 700, fontSize: '13px' }}>{node.id}</span>
                    {node.role === 'leader' && (
                      <span className="badge badge-accent">leader</span>
                    )}
                  </div>
                  <div style={{ fontSize: '10px', color: 'var(--muted)', fontFamily: 'monospace' }}>
                    {node.addr ?? 'addr unknown'}
                  </div>
                </div>
                <span
                  className={`badge ${
                    node.status === 'healthy'
                      ? 'badge-ok'
                      : node.status === 'unhealthy'
                      ? 'badge-error'
                      : node.status === 'draining'
                      ? 'badge-warn'
                      : 'badge-muted'
                  }`}
                >
                  {node.status}
                </span>
              </div>

              {/* Node details */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr',
                  gap: '8px',
                  marginBottom: '14px',
                }}
              >
                <div>
                  <div style={{ fontSize: '9px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '3px' }}>
                    Region
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text2)' }}>{node.region ?? '—'}</div>
                </div>
                <div>
                  <div style={{ fontSize: '9px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '3px' }}>
                    Policy v
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text2)' }}>{node.policy_version ?? '—'}</div>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <div style={{ fontSize: '9px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '3px' }}>
                    Last Seen
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text2)' }}>{fmtRelTime(node.last_seen)}</div>
                </div>
              </div>

              {/* Drain button */}
              <button
                className="btn btn-danger btn-sm"
                style={{ width: '100%' }}
                onClick={() => handleDrain(node.id)}
                disabled={drainingId === node.id || node.status === 'draining'}
              >
                {drainingId === node.id ? '…' : node.status === 'draining' ? 'Draining…' : '⬇ Drain Node'}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
