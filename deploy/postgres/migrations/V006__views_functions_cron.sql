-- ============================================================================
-- V006 — Operational views, stored procedures, pg_cron jobs
-- ============================================================================
SET search_path TO tsm, public;

-- ── View: live node status dashboard ─────────────────────────────────────────
CREATE OR REPLACE VIEW tsm.v_node_status AS
SELECT
    n.id,
    n.org_id,
    o.slug                                              AS org_slug,
    n.role,
    n.addr,
    n.healthy,
    n.consecutive_fails,
    n.policy_version,
    n.version_string,
    n.region,
    n.zone,
    n.last_seen_at,
    EXTRACT(EPOCH FROM (NOW() - n.last_seen_at))::INT   AS seconds_since_seen,
    n.labels
FROM tsm.nodes n
JOIN tsm.organizations o ON o.id = n.org_id;
COMMENT ON VIEW tsm.v_node_status IS 'Admin dashboard node health overview.';

-- ── View: audit summary per workspace (last 24h) ──────────────────────────────
CREATE OR REPLACE VIEW tsm.v_audit_summary_24h AS
SELECT
    a.workspace_id,
    w.slug                                             AS workspace_slug,
    a.org_id,
    COUNT(*)                                           AS total_requests,
    COUNT(*) FILTER (WHERE action = 'block')           AS blocked,
    COUNT(*) FILTER (WHERE action = 'redact')          AS redacted,
    COUNT(*) FILTER (WHERE action = 'allow')           AS allowed,
    COUNT(*) FILTER (WHERE action = 'rate_limited')    AS rate_limited,
    ROUND(AVG(risk_score)::numeric,1)                  AS avg_risk,
    ROUND((PERCENTILE_CONT(0.95) WITHIN GROUP
          (ORDER BY latency_ms))::numeric, 2)          AS p95_latency_ms,
    COUNT(*) FILTER
        (WHERE 'JAILBREAK' = ANY(pii_types))           AS jailbreak_attempts,
    COUNT(*) FILTER
        (WHERE severity = 'critical')                  AS critical_events,
    COUNT(DISTINCT client_ip)                          AS unique_clients,
    MIN(ts)                                            AS earliest,
    MAX(ts)                                            AS latest
FROM tsm.audit_log a
JOIN tsm.workspaces w ON w.id = a.workspace_id
WHERE a.ts > NOW() - INTERVAL '24 hours'
GROUP BY a.workspace_id, w.slug, a.org_id;
COMMENT ON VIEW tsm.v_audit_summary_24h IS 'Admin dashboard — last 24h KPIs per workspace.';

-- ── View: top threat sources (last 24h) ───────────────────────────────────────
CREATE OR REPLACE VIEW tsm.v_top_threats_24h AS
SELECT
    client_ip,
    org_id,
    workspace_id,
    COUNT(*)                                           AS request_count,
    COUNT(*) FILTER (WHERE action = 'block')           AS blocked_count,
    ROUND(AVG(risk_score)::numeric,1)                  AS avg_risk,
    ARRAY_AGG(DISTINCT unnested_pii) FILTER
        (WHERE unnested_pii IS NOT NULL)               AS pii_types_seen,
    MAX(ts)                                            AS last_seen
FROM tsm.audit_log
CROSS JOIN LATERAL UNNEST(pii_types) AS unnested_pii
WHERE ts > NOW() - INTERVAL '24 hours'
  AND action IN ('block','rate_limited')
GROUP BY client_ip, org_id, workspace_id
HAVING COUNT(*) >= 3
ORDER BY blocked_count DESC;
COMMENT ON VIEW tsm.v_top_threats_24h IS 'Top threat IPs for SIEM/SOC dashboards.';

-- ── View: policy coverage gaps ────────────────────────────────────────────────
-- Shows workspaces where a significant fraction of blocked requests matched no named rule.
CREATE OR REPLACE VIEW tsm.v_policy_gaps AS
SELECT
    workspace_id,
    COUNT(*) FILTER (WHERE rule_fired = '' OR rule_fired IS NULL) AS unmatched_blocks,
    COUNT(*)                                                      AS total_blocks,
    ROUND(100.0 * COUNT(*) FILTER (WHERE rule_fired = '' OR rule_fired IS NULL)
          / NULLIF(COUNT(*),0), 1)                                AS unmatched_pct
FROM tsm.audit_log
WHERE action = 'block'
  AND ts > NOW() - INTERVAL '7 days'
GROUP BY workspace_id
HAVING COUNT(*) FILTER (WHERE rule_fired = '' OR rule_fired IS NULL) > 0;

-- ── Stored procedure: record an audit event (called from Rust via libpq) ─────
-- Using a stored proc rather than raw INSERT gives us:
--   • HMAC chain continuation in a single round-trip
--   • Span insert in the same transaction
--   • Automatic metrics_hourly refresh scheduling
CREATE OR REPLACE FUNCTION tsm.record_audit_event(
    p_org_id          UUID,
    p_workspace_id    UUID,
    p_request_id      UUID,
    p_node_id         TEXT,
    p_client_ip       INET,
    p_method          TEXT,
    p_path            TEXT,
    p_model           TEXT,
    p_upstream        TEXT,
    p_action          TEXT,
    p_rule_fired      TEXT,
    p_pii_types       TEXT[],
    p_risk_score      NUMERIC,
    p_severity        TEXT,
    p_streamed        BOOLEAN,
    p_redacted        BOOLEAN,
    p_redact_spans    JSONB,
    p_latency_ms      NUMERIC,
    p_detector_ms     NUMERIC,
    p_upstream_ms     NUMERIC,
    p_prompt_tokens   INT,
    p_completion_tokens INT,
    p_prev_hash       TEXT,
    p_entry_hash      TEXT,
    p_traceparent     TEXT,
    p_tags            JSONB,
    -- Stage spans array: [{stage,elapsed_us,status}, ...]
    p_spans           JSONB DEFAULT '[]'
) RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE
    v_id BIGINT;
BEGIN
    INSERT INTO tsm.audit_log (
        org_id, workspace_id, request_id, node_id, client_ip,
        method, path, model, upstream,
        action, rule_fired, pii_types, risk_score, severity,
        streamed, redacted, redact_spans,
        latency_ms, detector_ms, upstream_ms,
        prompt_tokens, completion_tokens,
        prev_hash, entry_hash, traceparent, tags
    ) VALUES (
        p_org_id, p_workspace_id, p_request_id, p_node_id, p_client_ip,
        p_method, p_path, p_model, p_upstream,
        p_action, p_rule_fired, p_pii_types, p_risk_score, p_severity,
        p_streamed, p_redacted, p_redact_spans,
        p_latency_ms, p_detector_ms, p_upstream_ms,
        p_prompt_tokens, p_completion_tokens,
        p_prev_hash, p_entry_hash, p_traceparent, p_tags
    ) RETURNING id INTO v_id;

    -- Insert pipeline stage spans if provided
    IF jsonb_array_length(p_spans) > 0 THEN
        INSERT INTO tsm.audit_spans (request_id, ts, stage, elapsed_us, status)
        SELECT
            p_request_id,
            NOW(),
            (span->>'stage')::TEXT,
            (span->>'elapsed_us')::BIGINT,
            COALESCE(span->>'status', 'ok')
        FROM jsonb_array_elements(p_spans) AS span;
    END IF;

    RETURN v_id;
END;
$$;

-- ── pg_cron scheduled jobs (requires pg_cron extension) ──────────────────────
-- Install: CREATE EXTENSION pg_cron;
-- These are idempotent — safe to re-run.
DO $do$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        -- Refresh hourly metrics every hour at :01
        PERFORM cron.schedule('refresh-metrics-hourly', '1 * * * *',
            'REFRESH MATERIALIZED VIEW CONCURRENTLY tsm.metrics_hourly');

        -- Maintain audit partitions monthly (create future, drop expired)
        PERFORM cron.schedule('maintain-audit-partitions', '0 2 1 * *',
            'SELECT tsm.maintain_audit_partitions(13)');

        -- Maintain node health partitions daily
        PERFORM cron.schedule('maintain-node-health-partitions', '0 3 * * *',
            $$
            DO $inner$
            DECLARE d DATE; BEGIN
                FOR i IN 0..1 LOOP
                    d := CURRENT_DATE + i;
                    EXECUTE FORMAT(
                        'CREATE TABLE IF NOT EXISTS tsm.node_health_%s
                         PARTITION OF tsm.node_health_history
                         FOR VALUES FROM (%L) TO (%L)',
                        TO_CHAR(d,''YYYY_MM_DD''), d, d+1);
                END LOOP;
                -- Drop partitions older than 7 days
                DELETE FROM tsm.node_health_history
                WHERE ts < NOW() - INTERVAL ''7 days'';
            END; $inner$
            $$);

        -- Purge expired admin sessions daily
        PERFORM cron.schedule('purge-sessions', '30 3 * * *',
            'SELECT tsm.purge_expired_sessions()');

        RAISE NOTICE 'pg_cron jobs scheduled successfully';
    ELSE
        RAISE NOTICE 'pg_cron not installed — schedule jobs manually';
    END IF;
END;
$do$;

-- ── Row-level security (enable for multi-tenant isolation) ───────────────────
-- Each API key can only see rows for its own workspace_id.
-- Enable in production:  ALTER TABLE tsm.audit_log ENABLE ROW LEVEL SECURITY;
-- Policy example below (disabled by default — activate after testing):
--
-- CREATE POLICY audit_log_workspace_isolation ON tsm.audit_log
--     USING (workspace_id = current_setting('tsm.workspace_id')::UUID);
--
-- Set at connection time:  SET tsm.workspace_id = '<uuid>';
-- The Go/Rust layer sets this on each pooled connection checkout.

COMMENT ON SCHEMA tsm IS
    'TSM — The Sovereign Mechanica. All application objects live here.
     Set search_path = tsm, public for all application connections.
     Enable RLS policies before production deployment.';
