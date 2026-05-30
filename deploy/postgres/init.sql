-- TSM audit ledger + metrics schema
-- Applied automatically on first postgres startup

CREATE TABLE IF NOT EXISTS audit_events (
    id            BIGSERIAL PRIMARY KEY,
    ts            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id        TEXT        NOT NULL DEFAULT 'default',
    workspace_id  TEXT        NOT NULL DEFAULT 'default',
    request_id    UUID        NOT NULL DEFAULT gen_random_uuid(),
    model         TEXT,
    action        TEXT        NOT NULL,  -- allow|redact|block|route_local
    pii_types     TEXT[]      NOT NULL DEFAULT '{}',
    severity      TEXT        NOT NULL DEFAULT 'none',
    risk_score    NUMERIC(5,1),
    routed_local  BOOLEAN     NOT NULL DEFAULT FALSE,
    redacted      BOOLEAN     NOT NULL DEFAULT FALSE,
    latency_ms    NUMERIC(8,2),
    prompt_tokens INT,
    prev_hash     TEXT,
    entry_hash    TEXT,
    upstream      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_org     ON audit_events (org_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_events (action, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_pii     ON audit_events USING GIN (pii_types);

-- Workspace / org registry
CREATE TABLE IF NOT EXISTS workspaces (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL,
    name          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    policy_json   JSONB NOT NULL DEFAULT '{"rules": []}',
    rate_limit    INT  NOT NULL DEFAULT 100,  -- req/min
    active        BOOLEAN NOT NULL DEFAULT TRUE
);

INSERT INTO workspaces (id, org_id, name)
VALUES ('default', 'default', 'Default Workspace')
ON CONFLICT DO NOTHING;

-- Hourly rollup for dashboard performance
CREATE TABLE IF NOT EXISTS metrics_hourly (
    hour          TIMESTAMPTZ NOT NULL,
    org_id        TEXT        NOT NULL,
    total         INT         NOT NULL DEFAULT 0,
    blocked       INT         NOT NULL DEFAULT 0,
    redacted      INT         NOT NULL DEFAULT 0,
    routed_local  INT         NOT NULL DEFAULT 0,
    clean         INT         NOT NULL DEFAULT 0,
    avg_risk      NUMERIC(5,1),
    PRIMARY KEY (hour, org_id)
);

-- Retention: auto-delete events older than 90 days (configurable)
-- Run via cron or pg_cron extension in production
CREATE OR REPLACE FUNCTION purge_old_events(retention_days INT DEFAULT 90)
RETURNS INT LANGUAGE plpgsql AS $$
DECLARE deleted INT;
BEGIN
    DELETE FROM audit_events WHERE ts < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$;
