'use client';

import { useEffect, useState, useCallback } from 'react';

const ADMIN_URL = process.env.NEXT_PUBLIC_ADMIN_API_URL ?? 'http://localhost:9090';
const TOKEN = process.env.NEXT_PUBLIC_TSM_TOKEN ?? '';

// ── Types ────────────────────────────────────────────────────────────────────

interface AuditEntry {
  timestamp: string;
  request_id: string;
  client_ip?: string;
  action: string;
  model?: string;
  pii_types?: string[];
  risk_score?: number;
  severity?: string;
  user?: string;
  upstream?: string;
}

interface AuditResponse {
  entries?: AuditEntry[];
  content?: AuditEntry[];
  data?: AuditEntry[];
  total?: number;
  totalElements?: number;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = {};
  if (TOKEN) h['Authorization'] = `Bearer ${TOKEN}`;
  return h;
}

function fmtTs(iso: string) {
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-US', { hour12: false, month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return iso;
  }
}

function riskColor(score?: number) {
  if (score === undefined || score === null) return 'var(--muted)';
  if (score >= 80) return '#ef4444';
  if (score >= 55) return '#f59e0b';
  if (score >= 30) return '#3b82f6';
  return '#10b981';
}

function severityBadge(sev?: string) {
  if (!sev) return 'badge badge-muted';
  const s = sev.toLowerCase();
  if (s === 'critical') return 'badge badge-error';
  if (s === 'high') return 'badge badge-error';
  if (s === 'medium') return 'badge badge-warn';
  if (s === 'low') return 'badge badge-ok';
  return 'badge badge-muted';
}

function actionBadge(action: string) {
  const map: Record<string, string> = {
    block: 'badge badge-block',
    redact: 'badge badge-redact',
    allow: 'badge badge-allow',
    route_local: 'badge badge-local',
  };
  return map[action] ?? 'badge badge-muted';
}

const PAGE_SIZE = 50;

// ── Main component ───────────────────────────────────────────────────────────

export function AuditTab() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [actionFilter, setActionFilter] = useState<string>('all');
  const [searchId, setSearchId] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  // Debounce search input
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(searchId), 300);
    return () => clearTimeout(t);
  }, [searchId]);

  // ── Fetch audit log ───────────────────────────────────────────────────────
  const fetchAudit = useCallback(async (pg: number) => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        page: String(pg),
        size: String(PAGE_SIZE),
        sort: 'timestamp,desc',
      });
      const res = await fetch(`${ADMIN_URL}/api/audit?${params}`, {
        headers: authHeaders(),
        cache: 'no-store',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: AuditResponse | AuditEntry[] = await res.json();

      if (Array.isArray(data)) {
        setEntries(data);
        setTotal(data.length);
      } else {
        const arr = data.entries ?? data.content ?? data.data ?? [];
        setEntries(arr);
        setTotal(data.total ?? data.totalElements ?? arr.length);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load audit log');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAudit(page);
    // Refresh every 30s
    const id = setInterval(() => fetchAudit(page), 30_000);
    return () => clearInterval(id);
  }, [fetchAudit, page]);

  // ── Client-side filter ────────────────────────────────────────────────────
  const filtered = entries.filter(e => {
    const matchAction = actionFilter === 'all' || e.action === actionFilter;
    const q = debouncedSearch.toLowerCase();
    const matchSearch =
      !q ||
      e.request_id.toLowerCase().includes(q) ||
      (e.client_ip ?? '').toLowerCase().includes(q) ||
      (e.model ?? '').toLowerCase().includes(q);
    return matchAction && matchSearch;
  });

  const totalPages = Math.ceil(total / PAGE_SIZE);

  const changePage = (pg: number) => {
    setPage(pg);
    fetchAudit(pg);
  };

  const actions = ['all', 'block', 'redact', 'allow', 'route_local'];

  return (
    <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
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

      {/* Toolbar */}
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          className="input"
          type="text"
          placeholder="Search by request ID, IP, model…"
          value={searchId}
          onChange={e => setSearchId(e.target.value)}
          style={{ maxWidth: '280px', flex: '0 0 auto' }}
        />
        <div style={{ display: 'flex', gap: '4px' }}>
          {actions.map(a => (
            <button
              key={a}
              className={`btn btn-sm ${actionFilter === a ? 'btn-primary' : ''}`}
              onClick={() => setActionFilter(a)}
            >
              {a === 'all' ? 'All' : a}
            </button>
          ))}
        </div>
        {(actionFilter !== 'all' || searchId) && (
          <button
            className="btn btn-sm"
            onClick={() => { setActionFilter('all'); setSearchId(''); }}
            style={{ color: 'var(--muted)' }}
          >
            ✕ Clear
          </button>
        )}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ fontSize: '11px', color: 'var(--muted)' }}>
            {filtered.length} of {total.toLocaleString()} entries
          </span>
          <button className="btn btn-sm" onClick={() => fetchAudit(page)}>↻ Refresh</button>
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                {['Timestamp', 'Request ID', 'Client IP', 'Action', 'Model', 'PII Types', 'Risk', 'Severity'].map(h => (
                  <th key={h} style={{ padding: '12px 14px' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 8 }).map((__, j) => (
                      <td key={j} style={{ padding: '12px 14px' }}>
                        <div
                          className="shimmer"
                          style={{ height: '12px', borderRadius: '3px', width: j === 1 ? '140px' : '60px' }}
                        />
                      </td>
                    ))}
                  </tr>
                ))
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '48px', textAlign: 'center', color: 'var(--muted)' }}>
                    No audit entries found
                  </td>
                </tr>
              ) : (
                filtered.map((e, idx) => (
                  <tr key={`${e.request_id}-${idx}`}>
                    <td style={{ fontSize: '11px', color: 'var(--muted)', whiteSpace: 'nowrap', padding: '10px 14px' }}>
                      {fmtTs(e.timestamp)}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '10px', color: 'var(--text2)', padding: '10px 14px' }}>
                      <span className="truncate" style={{ display: 'block', maxWidth: '120px' }} title={e.request_id}>
                        {e.request_id}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--text2)', padding: '10px 14px', whiteSpace: 'nowrap' }}>
                      {e.client_ip ?? '—'}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span className={actionBadge(e.action)}>{e.action}</span>
                    </td>
                    <td style={{ fontSize: '11px', color: 'var(--text2)', padding: '10px 14px', maxWidth: '140px' }}>
                      <span className="truncate" style={{ display: 'block' }}>
                        {e.model ?? '—'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      {e.pii_types && e.pii_types.length > 0 ? (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px' }}>
                          {e.pii_types.slice(0, 2).map(t => (
                            <span
                              key={t}
                              style={{
                                fontSize: '9px',
                                padding: '1px 5px',
                                borderRadius: '3px',
                                background: 'var(--yellow-bg)',
                                color: 'var(--yellow)',
                                border: '1px solid rgba(245,158,11,0.15)',
                              }}
                            >
                              {t}
                            </span>
                          ))}
                          {e.pii_types.length > 2 && (
                            <span style={{ fontSize: '9px', color: 'var(--muted)' }}>
                              +{e.pii_types.length - 2}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span style={{ color: 'var(--muted)', fontSize: '11px' }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span
                        style={{
                          fontWeight: 700,
                          fontSize: '12px',
                          color: riskColor(e.risk_score),
                          fontVariantNumeric: 'tabular-nums',
                        }}
                      >
                        {e.risk_score ?? '—'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      {e.severity ? (
                        <span className={severityBadge(e.severity)}>{e.severity}</span>
                      ) : (
                        <span style={{ color: 'var(--muted)', fontSize: '11px' }}>—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)' }}>
            <div className="pagination">
              <button
                className="page-btn"
                onClick={() => changePage(0)}
                disabled={page === 0}
              >
                «
              </button>
              <button
                className="page-btn"
                onClick={() => changePage(Math.max(0, page - 1))}
                disabled={page === 0}
              >
                ‹
              </button>
              {Array.from({ length: Math.min(7, totalPages) }, (_, i) => {
                const start = Math.max(0, Math.min(page - 3, totalPages - 7));
                const pg = start + i;
                return (
                  <button
                    key={pg}
                    className={`page-btn ${pg === page ? 'active' : ''}`}
                    onClick={() => changePage(pg)}
                  >
                    {pg + 1}
                  </button>
                );
              })}
              <button
                className="page-btn"
                onClick={() => changePage(Math.min(totalPages - 1, page + 1))}
                disabled={page >= totalPages - 1}
              >
                ›
              </button>
              <button
                className="page-btn"
                onClick={() => changePage(totalPages - 1)}
                disabled={page >= totalPages - 1}
              >
                »
              </button>
              <span style={{ fontSize: '10px', color: 'var(--muted)', marginLeft: '8px' }}>
                Page {page + 1} of {totalPages} · {total.toLocaleString()} total
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
