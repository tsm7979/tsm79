-- ============================================================================
-- V003 — Policy store: snapshots, rules, rule history, policy signing keys
-- Replaces Go control plane's in-memory Store with durable PostgreSQL backing.
-- ============================================================================
SET search_path TO tsm, public;

-- ── Policy snapshots (versioned immutable policy state) ───────────────────────
CREATE TABLE tsm.policy_snapshots (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID        NOT NULL REFERENCES tsm.workspaces(id) ON DELETE CASCADE,
    version         BIGINT      NOT NULL,                  -- monotonically increasing per workspace
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID        REFERENCES tsm.users(id),
    change_summary  TEXT        NOT NULL DEFAULT '',       -- human description of change
    rules_json      JSONB       NOT NULL,                  -- full snapshot of all rules
    signature       TEXT,                                  -- Ed25519 sig over canonical JSON
    pub_key_id      UUID,                                  -- which signing key was used
    UNIQUE (workspace_id, version)
);
CREATE INDEX idx_snap_ws_ver ON tsm.policy_snapshots (workspace_id, version DESC);
COMMENT ON TABLE tsm.policy_snapshots IS
    'Immutable versioned policy snapshots. Each PUT /config/policy creates one row.';

-- ── Active rules (denormalized for fast lookup) ───────────────────────────────
-- Always reflects the current HEAD snapshot per workspace.
-- Rebuilt from policy_snapshots on apply.
CREATE TABLE tsm.policy_rules (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID        NOT NULL REFERENCES tsm.workspaces(id) ON DELETE CASCADE,
    snapshot_id     UUID        NOT NULL REFERENCES tsm.policy_snapshots(id) ON DELETE CASCADE,
    rule_name       TEXT        NOT NULL,
    priority        INT         NOT NULL DEFAULT 100,
    action          TEXT        NOT NULL CHECK (action IN ('allow','block','redact','route_local')),
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    condition_json  JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_id, snapshot_id, rule_name)
);
CREATE INDEX idx_rule_ws_active ON tsm.policy_rules (workspace_id, priority ASC)
    WHERE enabled = TRUE;
CREATE INDEX idx_rule_name      ON tsm.policy_rules USING GIN (rule_name tsm.gin_trgm_ops);
COMMENT ON TABLE tsm.policy_rules IS
    'Denormalized active rules for O(1) lookup. Rebuilt from policy_snapshots on each version bump.';

-- ── Rule change history (per-rule diff trail) ────────────────────────────────
CREATE TABLE tsm.rule_history (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID        NOT NULL REFERENCES tsm.workspaces(id) ON DELETE CASCADE,
    rule_name       TEXT        NOT NULL,
    event           TEXT        NOT NULL CHECK (event IN ('create','update','delete','enable','disable')),
    old_state       JSONB,
    new_state       JSONB,
    changed_by      UUID        REFERENCES tsm.users(id),
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    snapshot_version BIGINT     NOT NULL,
    source          TEXT        NOT NULL DEFAULT 'api'     -- api|suggestion|import|cli
);
CREATE INDEX idx_rh_rule_ws ON tsm.rule_history (workspace_id, rule_name, changed_at DESC);
COMMENT ON TABLE tsm.rule_history IS
    'Per-rule audit trail. Every PATCH /config/policy/rules inserts one row.';

-- ── Policy signing keys ───────────────────────────────────────────────────────
-- Stores the public half of Ed25519 keypairs used to sign policy snapshots.
-- The private key NEVER enters the database — it lives in HSM / Vault / filesystem.
CREATE TABLE tsm.policy_signing_keys (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES tsm.organizations(id) ON DELETE CASCADE,
    key_name        TEXT        NOT NULL,
    pub_key_b64     TEXT        NOT NULL,                  -- base64(32-byte Ed25519 public key)
    algorithm       TEXT        NOT NULL DEFAULT 'Ed25519',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    fingerprint     TEXT        NOT NULL,                  -- SHA-256(pub_key_b64)[0:16]
    UNIQUE (org_id, key_name)
);
CREATE INDEX idx_sigkey_org ON tsm.policy_signing_keys (org_id) WHERE revoked_at IS NULL;
COMMENT ON TABLE tsm.policy_signing_keys IS
    'Ed25519 public keys for verifying policy snapshot signatures. Private keys stored in Vault.';

-- ── Helper: get the current snapshot for a workspace ─────────────────────────
CREATE OR REPLACE FUNCTION tsm.current_snapshot(p_workspace_id UUID)
RETURNS tsm.policy_snapshots LANGUAGE sql STABLE AS $$
    SELECT * FROM tsm.policy_snapshots
    WHERE workspace_id = p_workspace_id
    ORDER BY version DESC
    LIMIT 1;
$$;

-- ── Helper: bump policy version atomically ────────────────────────────────────
-- Called by the Go control plane on every PUT/PATCH.
-- Returns the new snapshot ID and version number.
CREATE OR REPLACE FUNCTION tsm.create_snapshot(
    p_workspace_id  UUID,
    p_rules_json    JSONB,
    p_change_summary TEXT,
    p_created_by    UUID DEFAULT NULL,
    p_signature     TEXT DEFAULT NULL,
    p_pub_key_id    UUID DEFAULT NULL
) RETURNS TABLE(snapshot_id UUID, version BIGINT)
LANGUAGE plpgsql AS $$
DECLARE
    v_version  BIGINT;
    v_snap_id  UUID;
BEGIN
    SELECT COALESCE(MAX(ps.version), 0) + 1
    INTO   v_version
    FROM   tsm.policy_snapshots ps
    WHERE  ps.workspace_id = p_workspace_id;

    INSERT INTO tsm.policy_snapshots
        (workspace_id, version, created_by, change_summary, rules_json, signature, pub_key_id)
    VALUES
        (p_workspace_id, v_version, p_created_by, p_change_summary,
         p_rules_json, p_signature, p_pub_key_id)
    RETURNING id INTO v_snap_id;

    RETURN QUERY SELECT v_snap_id, v_version;
END;
$$;
