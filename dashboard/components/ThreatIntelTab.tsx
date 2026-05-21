'use client';

import { useEffect, useState, useCallback } from 'react';

const PROXY_URL = process.env.NEXT_PUBLIC_PROXY_URL ?? 'http://localhost:8080';

// ── Types ────────────────────────────────────────────────────────────────────

interface FeedStat {
  name: string;
  last_poll?: string;
  records: number;
  status: 'ok' | 'error' | 'pending';
  error?: string;
}

interface BlocklistEntry {
  ip: string;
  reason?: string;
  ttl_hours?: number;
  added_at?: string;
}

interface BlocklistResponse {
  entries: BlocklistEntry[];
  total?: number;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async function apiFetch<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

function fmtTime(iso?: string) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('en-US', { hour12: false });
  } catch {
    return iso;
  }
}

// ── Sub-components ───────────────────────────────────────────────────────────

function CountBadge({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div className="card-gradient-border" style={{ textAlign: 'center', padding: '16px' }}>
      <div
        className="stat-value"
        style={{ fontSize: '2rem', color: color ?? 'var(--accent2)' }}
      >
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function FeedsTable({ feeds, loading }: { feeds: FeedStat[]; loading: boolean }) {
  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {[1, 2, 3].map(i => (
          <div key={i} className="shimmer" style={{ height: '40px', borderRadius: '6px' }} />
        ))}
      </div>
    );
  }
  if (feeds.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⚡</div>
        <div className="empty-state-text">No threat feeds configured</div>
      </div>
    );
  }
  return (
    <table className="data-table">
      <thead>
        <tr>
          {['Feed Name', 'Last Poll', 'Records', 'Status', 'Error'].map(h => (
            <th key={h}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {feeds.map(f => (
          <tr key={f.name}>
            <td style={{ fontWeight: 600 }}>{f.name}</td>
            <td style={{ color: 'var(--muted)', fontSize: '11px' }}>{fmtTime(f.last_poll)}</td>
            <td>
              <span style={{ color: 'var(--text2)', fontVariantNumeric: 'tabular-nums' }}>
                {f.records.toLocaleString()}
              </span>
            </td>
            <td>
              <span className={`badge ${f.status === 'ok' ? 'badge-ok' : f.status === 'error' ? 'badge-error' : 'badge-muted'}`}>
                {f.status}
              </span>
            </td>
            <td style={{ color: 'var(--red)', fontSize: '11px', maxWidth: '200px' }}>
              <span className="truncate" style={{ display: 'block' }}>
                {f.error ?? '—'}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Main component ───────────────────────────────────────────────────────────

export function ThreatIntelTab() {
  const [feeds, setFeeds] = useState<FeedStat[]>([]);
  const [blocklistSize, setBlocklistSize] = useState<number>(0);
  const [torSize, setTorSize] = useState<number>(0);
  const [blocklist, setBlocklist] = useState<BlocklistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Manual block form state
  const [blockIp, setBlockIp] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [blockTtl, setBlockTtl] = useState('24');
  const [blocking, setBlocking] = useState(false);
  const [blockMsg, setBlockMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // Pagination
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 20;

  // ── Data fetching (auto-refresh every 30s) ────────────────────────────────
  const fetchData = useCallback(async () => {
    setError(null);
    try {
      const [feedsData, blSize, torSz, blData] = await Promise.allSettled([
        apiFetch<FeedStat[]>(`${PROXY_URL}/api/threat-intel/feeds`),
        apiFetch<{ size: number } | number>(`${PROXY_URL}/api/threat-intel/blocklist/size`),
        apiFetch<{ size: number } | number>(`${PROXY_URL}/api/threat-intel/tor-set-size`),
        apiFetch<BlocklistResponse | BlocklistEntry[]>(`${PROXY_URL}/api/threat-intel/blocklist`),
      ]);

      if (feedsData.status === 'fulfilled') setFeeds(feedsData.value);
      if (blSize.status === 'fulfilled') {
        const v = blSize.value;
        setBlocklistSize(typeof v === 'number' ? v : v.size);
      }
      if (torSz.status === 'fulfilled') {
        const v = torSz.value;
        setTorSize(typeof v === 'number' ? v : v.size);
      }
      if (blData.status === 'fulfilled') {
        const v = blData.value;
        setBlocklist(Array.isArray(v) ? v : v.entries);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load threat intel');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 30_000);
    return () => clearInterval(id);
  }, [fetchData]);

  // ── Block IP handler ──────────────────────────────────────────────────────
  const handleBlock = async () => {
    const ip = blockIp.trim();
    if (!ip) return;
    setBlocking(true);
    setBlockMsg(null);
    try {
      const res = await fetch(`${PROXY_URL}/api/threat-intel/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason: blockReason || 'manual', ttl_hours: Number(blockTtl) }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setBlockMsg({ ok: true, text: `${ip} added to blocklist` });
      setBlockIp('');
      setBlockReason('');
      setTimeout(fetchData, 800);
    } catch (e) {
      setBlockMsg({ ok: false, text: e instanceof Error ? e.message : 'Block failed' });
    } finally {
      setBlocking(false);
    }
  };

  const pagedEntries = blocklist.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const totalPages = Math.ceil(blocklist.length / PAGE_SIZE);

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
          {error} — some data may be unavailable
        </div>
      )}

      {/* Summary counts */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
        <CountBadge label="Blocklist IPs" value={blocklistSize} color="var(--red)" />
        <CountBadge label="Tor Exit Nodes" value={torSize} color="var(--yellow)" />
        <CountBadge label="Active Feeds" value={feeds.filter(f => f.status === 'ok').length} color="var(--green)" />
      </div>

      {/* Feed stats */}
      <div className="card">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '16px',
          }}
        >
          <div className="section-title" style={{ margin: 0 }}>Threat Feed Status</div>
          <button className="btn btn-sm" onClick={fetchData}>↻ Refresh</button>
        </div>
        <FeedsTable feeds={feeds} loading={loading} />
      </div>

      {/* Manual block form */}
      <div className="card">
        <div className="section-title">Manual Block</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto auto', gap: '10px', alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: '10px', color: 'var(--muted)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              IP Address
            </label>
            <input
              className="input"
              type="text"
              placeholder="203.0.113.42"
              value={blockIp}
              onChange={e => setBlockIp(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleBlock()}
            />
          </div>
          <div>
            <label style={{ fontSize: '10px', color: 'var(--muted)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Reason
            </label>
            <input
              className="input"
              type="text"
              placeholder="manual review"
              value={blockReason}
              onChange={e => setBlockReason(e.target.value)}
            />
          </div>
          <div>
            <label style={{ fontSize: '10px', color: 'var(--muted)', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              TTL (hrs)
            </label>
            <input
              className="input"
              type="number"
              min="1"
              max="8760"
              value={blockTtl}
              onChange={e => setBlockTtl(e.target.value)}
              style={{ width: '80px' }}
            />
          </div>
          <button
            className="btn btn-danger"
            onClick={handleBlock}
            disabled={blocking || !blockIp.trim()}
            style={{ height: '34px', alignSelf: 'flex-end' }}
          >
            {blocking ? '…' : '✕ Block'}
          </button>
        </div>
        {blockMsg && (
          <div
            style={{
              marginTop: '10px',
              padding: '7px 12px',
              borderRadius: '6px',
              fontSize: '11px',
              background: blockMsg.ok ? 'var(--green-bg)' : 'var(--red-bg)',
              color: blockMsg.ok ? 'var(--green)' : 'var(--red)',
              border: `1px solid ${blockMsg.ok ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
            }}
          >
            {blockMsg.text}
          </div>
        )}
      </div>

      {/* Blocklist table */}
      <div className="card">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '16px',
          }}
        >
          <div className="section-title" style={{ margin: 0 }}>
            Blocked IPs
            <span style={{ color: 'var(--accent2)', marginLeft: '8px' }}>
              {blocklist.length.toLocaleString()}
            </span>
          </div>
        </div>

        {pagedEntries.length === 0 && !loading ? (
          <div className="empty-state">
            <div className="empty-state-icon">◎</div>
            <div className="empty-state-text">No blocked IPs</div>
          </div>
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  {['IP Address', 'Reason', 'TTL (hrs)', 'Added At'].map(h => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pagedEntries.map((entry, i) => (
                  <tr key={`${entry.ip}-${i}`}>
                    <td style={{ fontFamily: 'monospace', color: 'var(--red)', fontWeight: 600 }}>
                      {entry.ip}
                    </td>
                    <td style={{ color: 'var(--text2)', fontSize: '11px' }}>
                      {entry.reason ?? '—'}
                    </td>
                    <td style={{ color: 'var(--muted)', fontSize: '11px' }}>
                      {entry.ttl_hours ?? '—'}
                    </td>
                    <td style={{ color: 'var(--muted)', fontSize: '11px' }}>
                      {fmtTime(entry.added_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {totalPages > 1 && (
              <div className="pagination">
                <button
                  className="page-btn"
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                >
                  ‹
                </button>
                {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                  const pg = page < 4 ? i : page - 3 + i;
                  if (pg >= totalPages) return null;
                  return (
                    <button
                      key={pg}
                      className={`page-btn ${pg === page ? 'active' : ''}`}
                      onClick={() => setPage(pg)}
                    >
                      {pg + 1}
                    </button>
                  );
                })}
                <button
                  className="page-btn"
                  onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                >
                  ›
                </button>
                <span style={{ fontSize: '10px', color: 'var(--muted)', marginLeft: '8px' }}>
                  {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, blocklist.length)} of {blocklist.length}
                </span>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
