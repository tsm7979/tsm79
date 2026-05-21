-- ============================================================================
-- V005 — Cluster nodes, alert rules, alert events, admin sessions
-- ============================================================================
SET search_path TO tsm, public;

-- ── Cluster nodes (replaces Go in-memory registry) ───────────────────────────
CREATE TABLE tsm.nodes (
    id               TEXT        PRIMARY KEY,              -- e.g. "dp-us-east-1-a"
    org_id           UUID        NOT NULL REFERENCES tsm.organizations(id) ON DELETE CASCADE,
    role             TEXT        NOT NULL CHECK (role IN ('dataplane','detector','control-plane')),
    addr             TEXT        NOT NULL,                 -- host:port
    health_path      TEXT        NOT NULL DEFAULT '/health',
    registered_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    healthy          BOOLEAN     NOT NULL DEFAULT TRUE,
    consecutive_fails INT        NOT NULL DEFAULT 0,
    policy_version   BIGINT      NOT NULL DEFAULT 0,       -- last ACK'd policy version
    version_string   TEXT,                                 -- binary version (from /health)
    region           TEXT        NOT NULL DEFAULT 'default',
    zone             TEXT,
    labels           JSONB       NOT NULL DEFAULT '{}',
    metadata         JSONB       NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_node_org_role ON tsm.nodes (org_id, role);
CREATE INDEX idx_node_healthy  ON tsm.nodes (org_id, role) WHERE healthy = TRUE;
COMMENT ON TABLE tsm.nodes IS
    'Durable cluster node registry. Replaces Go control plane in-memory registry.';

-- Node health history (time-series, pruned to 7 days)
CREATE TABLE tsm.node_health_history (
    node_id     TEXT        NOT NULL REFERENCES tsm.nodes(id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    healthy     BOOLEAN     NOT NULL,
    latency_ms  NUMERIC(8,2),
    status_code INT,
    error_msg   TEXT,
    PRIMARY KEY (node_id, ts)
) PARTITION BY RANGE (ts);

-- Create initial partitions (7 days rolling)
DO $$ DECLARE d DATE; BEGIN
    FOR i IN 0..8 LOOP
        d := CURRENT_DATE - i;
        EXECUTE FORMAT(
            'CREATE TABLE IF NOT EXISTS tsm.node_health_%s
             PARTITION OF tsm.node_health_history
             FOR VALUES FROM (%L) TO (%L)',
            TO_CHAR(d, 'YYYY_MM_DD'), d, d + 1
        );
    END LOOP;
END; $$;

-- ── Alert rules ───────────────────────────────────────────────────────────────
CREATE TABLE tsm.alert_rules (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID        REFERENCES tsm.workspaces(id) ON DELETE CASCADE,  -- NULL = org-wide
    org_id          UUID        NOT NULL REFERENCES tsm.organizations(id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    description     TEXT        NOT NULL DEFAULT '',
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Condition
    metric          TEXT        NOT NULL,                  -- block_rate|risk_p95|jailbreak_count|etc.
    operator        TEXT        NOT NULL CHECK (operator IN ('gt','gte','lt','lte','eq','neq')),
    threshold       NUMERIC     NOT NULL,
    window_minutes  INT         NOT NULL DEFAULT 5,
    -- Notification
    channels        JSONB       NOT NULL DEFAULT '[]',     -- [{type:slack,webhook:...},...]
    severity        TEXT        NOT NULL DEFAULT 'medium'
                                CHECK (severity IN ('low','medium','high','critical')),
    -- State
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID        REFERENCES tsm.users(id),
    last_fired_at   TIMESTAMPTZ,
    cooldown_minutes INT        NOT NULL DEFAULT 15,       -- min gap between firings
    UNIQUE (org_id, name)
);
CREATE INDEX idx_alert_ws     ON tsm.alert_rules (workspace_id) WHERE enabled = TRUE;
CREATE INDEX idx_alert_org    ON tsm.alert_rules (org_id)        WHERE enabled = TRUE;

-- Default system alert rules
INSERT INTO tsm.alert_rules
    (org_id, name, description, metric, operator, threshold, window_minutes, severity, channels)
SELECT
    o.id,
    rule.name,
    rule.description,
    rule.metric,
    rule.operator,
    rule.threshold,
    rule.window_minutes,
    rule.severity,
    rule.channels::JSONB
FROM tsm.organizations o,
(VALUES
  ('high-block-rate',   'Block rate > 20% over 5 min',       'block_rate', 'gt', 20,  5,  'high',     '[]'),
  ('jailbreak-spike',   'Jailbreak attempts > 10 in 5 min',  'jailbreak_count','gt', 10, 5, 'critical','[]'),
  ('p95-latency-high',  'P95 latency > 2000ms over 5 min',   'p95_latency_ms','gt',2000,5, 'medium',  '[]'),
  ('critical-pii-leak', 'Critical PII detected > 5 in 1 min','critical_pii_count','gt',5,1,'critical','[]')
) AS rule(name,description,metric,operator,threshold,window_minutes,severity,channels)
ON CONFLICT DO NOTHING;

-- ── Alert events (fired alerts history) ──────────────────────────────────────
CREATE TABLE tsm.alert_events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID        NOT NULL REFERENCES tsm.alert_rules(id) ON DELETE CASCADE,
    org_id          UUID        NOT NULL,
    fired_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    ack_at          TIMESTAMPTZ,
    ack_by          UUID        REFERENCES tsm.users(id),
    ack_note        TEXT,
    metric_value    NUMERIC     NOT NULL,                  -- value that triggered the alert
    context_json    JSONB       NOT NULL DEFAULT '{}',     -- snapshot of relevant metrics
    notified        BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE INDEX idx_aev_rule    ON tsm.alert_events (rule_id, fired_at DESC);
CREATE INDEX idx_aev_org     ON tsm.alert_events (org_id,  fired_at DESC);
CREATE INDEX idx_aev_open    ON tsm.alert_events (org_id)  WHERE resolved_at IS NULL;

-- ── Admin sessions (JWT refresh token store) ─────────────────────────────────
-- Access tokens are short-lived (15 min) and not stored.
-- Refresh tokens are stored here with a 30-day TTL.
CREATE TABLE tsm.admin_sessions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES tsm.users(id) ON DELETE CASCADE,
    token_hash      TEXT        NOT NULL UNIQUE,           -- SHA-256(refresh_token)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address      INET,
    user_agent      TEXT,
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX idx_sess_user   ON tsm.admin_sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_sess_expiry ON tsm.admin_sessions (expires_at) WHERE revoked_at IS NULL;

-- Auto-clean expired sessions (run via pg_cron daily)
CREATE OR REPLACE FUNCTION tsm.purge_expired_sessions() RETURNS INT
LANGUAGE sql AS $$
    WITH del AS (
        DELETE FROM tsm.admin_sessions
        WHERE expires_at < NOW() OR revoked_at IS NOT NULL
        RETURNING id
    ) SELECT count(*) FROM del;
$$;
