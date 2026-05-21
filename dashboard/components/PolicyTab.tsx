'use client';

import { useEffect, useState, useCallback } from 'react';

const ADMIN_URL = process.env.NEXT_PUBLIC_ADMIN_API_URL ?? 'http://localhost:9090';
const TOKEN = process.env.NEXT_PUBLIC_TSM_TOKEN ?? '';

// ── Types ────────────────────────────────────────────────────────────────────

interface PolicyCondition {
  field?: string;
  op?: string;
  value?: string | number | boolean;
  [key: string]: unknown;
}

interface PolicyRule {
  name: string;
  priority?: number;
  action: string;
  enabled: boolean;
  conditions?: PolicyCondition[];
  description?: string;
}

interface PolicyDoc {
  name?: string;
  version?: string | number;
  rules: PolicyRule[];
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (TOKEN) h['Authorization'] = `Bearer ${TOKEN}`;
  return h;
}

function fmtConditions(conds?: PolicyCondition[]) {
  if (!conds || conds.length === 0) return '—';
  return conds
    .map(c => c.field ? `${c.field} ${c.op ?? '='} ${c.value}` : JSON.stringify(c))
    .join(' AND ');
}

function actionColor(action: string) {
  if (action === 'block') return 'var(--red)';
  if (action === 'redact') return 'var(--yellow)';
  if (action === 'allow') return 'var(--green)';
  if (action === 'route_local') return 'var(--blue)';
  return 'var(--text2)';
}

function actionBadge(action: string) {
  if (action === 'block') return 'badge badge-block';
  if (action === 'redact') return 'badge badge-redact';
  if (action === 'allow') return 'badge badge-allow';
  if (action === 'route_local') return 'badge badge-local';
  return 'badge badge-muted';
}

// ── Main component ───────────────────────────────────────────────────────────

export function PolicyTab() {
  const [policy, setPolicy] = useState<PolicyDoc | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Editor state
  const [editorJson, setEditorJson] = useState('');
  const [editorError, setEditorError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // Toggle state (local overlay until next fetch)
  const [toggleOverrides, setToggleOverrides] = useState<Record<string, boolean>>({});
  const [toggling, setToggling] = useState<string | null>(null);

  // ── Fetch policy ──────────────────────────────────────────────────────────
  const fetchPolicy = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch(`${ADMIN_URL}/api/policy`, {
        headers: TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {},
        cache: 'no-store',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: PolicyDoc = await res.json();
      setPolicy(data);
      setEditorJson(JSON.stringify(data, null, 2));
      setToggleOverrides({});
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load policy');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPolicy();
  }, [fetchPolicy]);

  // ── Save policy ───────────────────────────────────────────────────────────
  const handleSave = async () => {
    setSaving(true);
    setSaveMsg(null);
    setEditorError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(editorJson);
    } catch (e) {
      setEditorError('Invalid JSON: ' + (e instanceof Error ? e.message : 'parse error'));
      setSaving(false);
      return;
    }
    try {
      const res = await fetch(`${ADMIN_URL}/api/policy/default`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify(parsed),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setSaveMsg({ ok: true, text: 'Policy saved successfully' });
      setTimeout(fetchPolicy, 800);
    } catch (e) {
      setSaveMsg({ ok: false, text: e instanceof Error ? e.message : 'Save failed' });
    } finally {
      setSaving(false);
    }
  };

  // ── Toggle rule ───────────────────────────────────────────────────────────
  const handleToggle = async (ruleName: string, currentEnabled: boolean) => {
    const newEnabled = !currentEnabled;
    setToggling(ruleName);
    // Optimistic update
    setToggleOverrides(prev => ({ ...prev, [ruleName]: newEnabled }));

    if (!policy) { setToggling(null); return; }

    const updatedPolicy: PolicyDoc = {
      ...policy,
      rules: policy.rules.map(r =>
        r.name === ruleName ? { ...r, enabled: newEnabled } : r
      ),
    };

    try {
      const res = await fetch(`${ADMIN_URL}/api/policy/default`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify(updatedPolicy),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      // Sync editor
      setEditorJson(JSON.stringify(updatedPolicy, null, 2));
      setPolicy(updatedPolicy);
      setToggleOverrides(prev => { const n = { ...prev }; delete n[ruleName]; return n; });
    } catch {
      // Revert optimistic update
      setToggleOverrides(prev => { const n = { ...prev }; delete n[ruleName]; return n; });
    } finally {
      setToggling(null);
    }
  };

  // ── Render ────────────────────────────────────────────────────────────────
  const rules = policy?.rules ?? [];

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

      {/* Policy metadata */}
      {policy && (
        <div className="card-gradient-border" style={{ padding: '14px 20px' }}>
          <div style={{ display: 'flex', gap: '32px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div>
              <div className="stat-label">Policy Name</div>
              <div style={{ fontWeight: 600, marginTop: '3px' }}>{policy.name ?? 'default'}</div>
            </div>
            <div>
              <div className="stat-label">Version</div>
              <div style={{ fontWeight: 600, marginTop: '3px' }}>{policy.version ?? '—'}</div>
            </div>
            <div>
              <div className="stat-label">Total Rules</div>
              <div style={{ fontWeight: 600, color: 'var(--accent2)', marginTop: '3px' }}>
                {rules.length}
              </div>
            </div>
            <div>
              <div className="stat-label">Enabled</div>
              <div style={{ fontWeight: 600, color: 'var(--green)', marginTop: '3px' }}>
                {rules.filter(r => {
                  const ov = toggleOverrides[r.name];
                  return ov !== undefined ? ov : r.enabled;
                }).length}
              </div>
            </div>
            <button className="btn btn-sm" onClick={fetchPolicy} style={{ marginLeft: 'auto' }}>
              ↻ Reload
            </button>
          </div>
        </div>
      )}

      {/* Rules table */}
      <div className="card">
        <div className="section-title">Rules</div>
        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="shimmer" style={{ height: '44px', borderRadius: '6px' }} />
            ))}
          </div>
        ) : rules.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">◎</div>
            <div className="empty-state-text">No rules defined</div>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  {['Name', 'Priority', 'Action', 'Enabled', 'Conditions', 'Toggle'].map(h => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[...rules]
                  .sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0))
                  .map(rule => {
                    const enabled =
                      toggleOverrides[rule.name] !== undefined
                        ? toggleOverrides[rule.name]
                        : rule.enabled;
                    return (
                      <tr
                        key={rule.name}
                        style={{ opacity: enabled ? 1 : 0.5, transition: 'opacity 0.2s' }}
                      >
                        <td style={{ fontWeight: 600 }}>
                          <div>{rule.name}</div>
                          {rule.description && (
                            <div style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '2px' }}>
                              {rule.description}
                            </div>
                          )}
                        </td>
                        <td style={{ color: 'var(--text2)', textAlign: 'center' }}>
                          {rule.priority ?? '—'}
                        </td>
                        <td>
                          <span className={actionBadge(rule.action)}>
                            {rule.action}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <span
                            style={{
                              fontSize: '11px',
                              fontWeight: 600,
                              color: enabled ? 'var(--green)' : 'var(--muted)',
                            }}
                          >
                            {enabled ? 'YES' : 'NO'}
                          </span>
                        </td>
                        <td
                          style={{
                            fontSize: '11px',
                            color: 'var(--text2)',
                            maxWidth: '240px',
                          }}
                        >
                          <span className="truncate" style={{ display: 'block', maxWidth: '240px' }}>
                            {fmtConditions(rule.conditions)}
                          </span>
                        </td>
                        <td>
                          <button
                            className={`btn btn-sm ${enabled ? 'btn-danger' : ''}`}
                            style={enabled ? {} : { color: 'var(--green)', borderColor: 'rgba(16,185,129,0.3)', background: 'var(--green-bg)' }}
                            onClick={() => handleToggle(rule.name, enabled)}
                            disabled={toggling === rule.name}
                          >
                            {toggling === rule.name ? '…' : enabled ? 'Disable' : 'Enable'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* JSON editor */}
      <div className="card">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '14px',
          }}
        >
          <div className="section-title" style={{ margin: 0 }}>JSON Editor</div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              className="btn btn-sm"
              onClick={() => policy && setEditorJson(JSON.stringify(policy, null, 2))}
            >
              ↩ Reset
            </button>
            <button
              className="btn btn-primary btn-sm"
              onClick={handleSave}
              disabled={saving}
            >
              {saving ? '…' : '▲ Save Policy'}
            </button>
          </div>
        </div>
        {editorError && (
          <div
            style={{
              marginBottom: '10px',
              padding: '7px 12px',
              borderRadius: '6px',
              background: 'var(--red-bg)',
              color: 'var(--red)',
              fontSize: '11px',
              border: '1px solid rgba(239,68,68,0.2)',
            }}
          >
            {editorError}
          </div>
        )}
        {saveMsg && (
          <div
            style={{
              marginBottom: '10px',
              padding: '7px 12px',
              borderRadius: '6px',
              background: saveMsg.ok ? 'var(--green-bg)' : 'var(--red-bg)',
              color: saveMsg.ok ? 'var(--green)' : 'var(--red)',
              fontSize: '11px',
              border: `1px solid ${saveMsg.ok ? 'rgba(16,185,129,0.2)' : 'rgba(239,68,68,0.2)'}`,
            }}
          >
            {saveMsg.text}
          </div>
        )}
        <textarea
          className="json-editor"
          value={editorJson}
          onChange={e => { setEditorJson(e.target.value); setEditorError(null); setSaveMsg(null); }}
          spellCheck={false}
          rows={20}
          placeholder={loading ? 'Loading policy…' : 'Enter policy JSON…'}
        />
        <div style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '8px' }}>
          PUT {ADMIN_URL}/api/policy/default · Requires Bearer token
        </div>
      </div>
    </div>
  );
}
