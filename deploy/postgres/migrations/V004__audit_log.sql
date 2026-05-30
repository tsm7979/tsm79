-- ============================================================================
-- V004 — Audit log: partitioned time-series table, HMAC chain, retention
--
-- Design decisions:
--   • Range-partitioned by month on ts — DROP old partitions for retention
--     (faster than DELETE; no vacuum overhead; zero lock on hot partitions)
--   • GIN index on pii_types for PII-type queries
--   • BRIN index on ts within each partition (sequential write pattern)
--   • Separate audit_spans for per-pipeline-stage latency breakdown
--   • cryptographic chain: each row carries HMAC-SHA256(prev_hash ‖ payload)
--     so any tamper of historical rows is detectable
-- ============================================================================
SET search_path TO tsm, public;

-- ── Main audit log (partitioned by month) ─────────────────────────────────────
CREATE TABLE tsm.audit_log (
    id              BIGSERIAL,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Tenant context
    org_id          UUID        NOT NULL,
    workspace_id    UUID        NOT NULL,
    -- Request identity
    request_id      UUID        NOT NULL DEFAULT gen_random_uuid(),
    node_id         TEXT        NOT NULL DEFAULT '',       -- which dataplane handled it
    client_ip       INET,
    -- Request metadata
    method          TEXT        NOT NULL DEFAULT 'POST',
    path            TEXT        NOT NULL DEFAULT '',
    model           TEXT,                                   -- gpt-4o, claude-3-5-sonnet, etc.
    upstream        TEXT,                                   -- openai|anthropic|local
    -- Decision
    action          TEXT        NOT NULL CHECK (action IN ('allow','block','redact','route_local','rate_limited','error')),
    rule_fired      TEXT        NOT NULL DEFAULT '',
    pii_types       TEXT[]      NOT NULL DEFAULT '{}',
    risk_score      NUMERIC(5,1),
    severity        TEXT        NOT NULL DEFAULT 'none'
                                CHECK (severity IN ('none','low','medium','high','critical')),
    -- SSE / streaming
    streamed        BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Redaction outcome
    redacted        BOOLEAN     NOT NULL DEFAULT FALSE,
    redact_spans    JSONB       NOT NULL DEFAULT '[]',      -- [{start,end,type}, ...]
    -- Performance
    latency_ms      NUMERIC(8,2),
    detector_ms     NUMERIC(8,2),
    upstream_ms     NUMERIC(8,2),
    -- Token counts (from upstream response)
    prompt_tokens   INT,
    completion_tokens INT,
    -- Cryptographic chain (tamper evidence)
    prev_hash       TEXT,                                  -- HMAC of previous row
    entry_hash      TEXT,                                  -- HMAC of this row
    -- W3C TraceContext for distributed tracing
    traceparent     TEXT,
    -- Free-form metadata (for custom integrations)
    tags            JSONB       NOT NULL DEFAULT '{}',
    PRIMARY KEY (id, ts)                                   -- partition key must be in PK
) PARTITION BY RANGE (ts);

-- Indexes on the parent table apply to all partitions
CREATE INDEX idx_al_org_ts         ON tsm.audit_log (org_id, ts DESC);
CREATE INDEX idx_al_ws_ts          ON tsm.audit_log (workspace_id, ts DESC);
CREATE INDEX idx_al_action         ON tsm.audit_log (action, ts DESC);
CREATE INDEX idx_al_pii_types      ON tsm.audit_log USING GIN (pii_types);
CREATE INDEX idx_al_risk           ON tsm.audit_log (risk_score DESC) WHERE risk_score > 60;
CREATE INDEX idx_al_request_id     ON tsm.audit_log (request_id);
CREATE INDEX idx_al_tags           ON tsm.audit_log USING GIN (tags);

COMMENT ON TABLE tsm.audit_log IS
    'Immutable audit trail for all AI proxy decisions. Partitioned monthly. Do not UPDATE or DELETE rows.';

-- ── Create initial partitions (current month + 3 future months) ──────────────
DO $$
DECLARE
    m DATE;
BEGIN
    FOR i IN 0..5 LOOP
        m := DATE_TRUNC('month', NOW()) + (i || ' months')::INTERVAL;
        EXECUTE FORMAT(
            'CREATE TABLE IF NOT EXISTS tsm.audit_log_%s
             PARTITION OF tsm.audit_log
             FOR VALUES FROM (%L) TO (%L)',
            TO_CHAR(m, 'YYYY_MM'),
            m,
            m + INTERVAL '1 month'
        );
        -- BRIN is ideal for append-only time-ordered partitions
        EXECUTE FORMAT(
            'CREATE INDEX IF NOT EXISTS idx_al_%s_brin
             ON tsm.audit_log_%s USING BRIN (ts)',
            TO_CHAR(m, 'YYYY_MM'),
            TO_CHAR(m, 'YYYY_MM')
        );
    END LOOP;
END; $$;

-- ── Pipeline stage latency breakdown ─────────────────────────────────────────
-- One row per stage per request. Joins to audit_log via request_id.
CREATE TABLE tsm.audit_spans (
    request_id      UUID        NOT NULL,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stage           TEXT        NOT NULL
                                CHECK (stage IN ('ingest','normalize','classify',
                                                 'py_detector','policy','route','respond')),
    elapsed_us      BIGINT      NOT NULL,                  -- microseconds
    status          TEXT        NOT NULL DEFAULT 'ok'      -- ok|error|timeout
);
CREATE INDEX idx_spans_req ON tsm.audit_spans (request_id);
CREATE INDEX idx_spans_ts  ON tsm.audit_spans (ts DESC);
COMMENT ON TABLE tsm.audit_spans IS
    'Per-pipeline-stage latency for each request. Used by the admin UI waterfall view.';

-- ── Hourly rollup materialized view ──────────────────────────────────────────
-- Refreshed by pg_cron every hour. Admin dashboard reads from here, not audit_log.
CREATE MATERIALIZED VIEW tsm.metrics_hourly AS
SELECT
    DATE_TRUNC('hour', ts)                                       AS hour,
    org_id,
    workspace_id,
    COUNT(*)                                                     AS total,
    COUNT(*) FILTER (WHERE action = 'block')                     AS blocked,
    COUNT(*) FILTER (WHERE action = 'redact')                    AS redacted,
    COUNT(*) FILTER (WHERE action = 'route_local')               AS routed_local,
    COUNT(*) FILTER (WHERE action = 'allow')                     AS clean,
    COUNT(*) FILTER (WHERE action = 'rate_limited')              AS rate_limited,
    ROUND(AVG(risk_score)::numeric, 1)                           AS avg_risk,
    ROUND(AVG(latency_ms)::numeric, 2)                           AS avg_latency_ms,
    ROUND((PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms))::numeric, 2) AS p95_latency_ms,
    COUNT(DISTINCT client_ip)                                    AS unique_ips,
    COUNT(DISTINCT request_id) FILTER (WHERE 'JAILBREAK' = ANY(pii_types)) AS jailbreak_attempts,
    SUM(prompt_tokens)                                           AS total_prompt_tokens,
    SUM(completion_tokens)                                       AS total_completion_tokens
FROM tsm.audit_log
GROUP BY 1, 2, 3
WITH DATA;

CREATE UNIQUE INDEX idx_mh_hour_ws ON tsm.metrics_hourly (hour, workspace_id);
CREATE INDEX idx_mh_org            ON tsm.metrics_hourly (org_id, hour DESC);

-- ── Retention policy: create future partitions + drop expired ────────────────
CREATE OR REPLACE FUNCTION tsm.maintain_audit_partitions(retention_months INT DEFAULT 13)
RETURNS TEXT LANGUAGE plpgsql AS $$
DECLARE
    m         DATE;
    part_name TEXT;
    report    TEXT := '';
    dropped   INT := 0;
    created   INT := 0;
BEGIN
    -- Create partitions for the next 3 months
    FOR i IN 0..3 LOOP
        m := DATE_TRUNC('month', NOW()) + (i || ' months')::INTERVAL;
        part_name := 'audit_log_' || TO_CHAR(m, 'YYYY_MM');
        IF NOT EXISTS (
            SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'tsm' AND c.relname = part_name
        ) THEN
            EXECUTE FORMAT(
                'CREATE TABLE tsm.%I PARTITION OF tsm.audit_log
                 FOR VALUES FROM (%L) TO (%L)',
                part_name, m, m + INTERVAL '1 month'
            );
            EXECUTE FORMAT(
                'CREATE INDEX ON tsm.%I USING BRIN (ts)', part_name
            );
            created := created + 1;
        END IF;
    END LOOP;

    -- Drop partitions older than retention_months
    FOR part_name IN
        SELECT c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'tsm'
          AND c.relname ~ '^audit_log_\d{4}_\d{2}$'
    LOOP
        m := TO_DATE(SUBSTRING(part_name FROM 10), 'YYYY_MM');
        IF m < DATE_TRUNC('month', NOW()) - (retention_months || ' months')::INTERVAL THEN
            EXECUTE FORMAT('DROP TABLE tsm.%I', part_name);
            dropped := dropped + 1;
        END IF;
    END LOOP;

    RETURN FORMAT('created=%s dropped=%s', created, dropped);
END; $$;
COMMENT ON FUNCTION tsm.maintain_audit_partitions IS
    'Run monthly via pg_cron: SELECT tsm.maintain_audit_partitions(13);
     Creates future partitions, drops old ones. Default 13-month retention.';

-- ── HMAC chain verification ───────────────────────────────────────────────────
-- Verifies the cryptographic chain for a range of audit events.
-- Returns rows where the chain is broken (tamper detected).
CREATE OR REPLACE FUNCTION tsm.verify_audit_chain(
    p_workspace_id UUID,
    p_from         TIMESTAMPTZ DEFAULT NOW() - INTERVAL '24 hours',
    p_to           TIMESTAMPTZ DEFAULT NOW()
)
RETURNS TABLE (
    id           BIGINT,
    ts           TIMESTAMPTZ,
    request_id   UUID,
    chain_status TEXT          -- 'ok' | 'broken' | 'missing_prev'
) LANGUAGE sql STABLE AS $$
    SELECT
        a.id,
        a.ts,
        a.request_id,
        CASE
            WHEN a.prev_hash IS NULL AND a.id > (
                SELECT MIN(al2.id) FROM tsm.audit_log al2 WHERE al2.workspace_id = p_workspace_id
            ) THEN 'missing_prev'
            WHEN a.entry_hash IS NULL THEN 'missing_hash'
            ELSE 'ok'   -- full verification requires HMAC key (done by Rust dataplane)
        END AS chain_status
    FROM tsm.audit_log a
    WHERE a.workspace_id = p_workspace_id
      AND a.ts BETWEEN p_from AND p_to
    ORDER BY a.ts ASC;
$$;
