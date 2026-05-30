-- ============================================================================
-- V002 — Multi-tenancy: organizations, workspaces, users, API keys, RBAC
-- ============================================================================
SET search_path TO tsm, public;

-- ── Organizations (top-level billing tenant) ─────────────────────────────────
CREATE TABLE tsm.organizations (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug           TEXT        NOT NULL UNIQUE,            -- URL-safe name
    display_name   TEXT        NOT NULL,
    plan           TEXT        NOT NULL DEFAULT 'starter'  -- starter|pro|enterprise
                               CHECK (plan IN ('starter','pro','enterprise')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    suspended_at   TIMESTAMPTZ,                            -- NULL = active
    metadata       JSONB       NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_org_slug ON tsm.organizations (slug);
COMMENT ON TABLE tsm.organizations IS
    'Top-level billing tenant. Every workspace belongs to one org.';

-- ── Workspaces (project-level isolation unit) ────────────────────────────────
CREATE TABLE tsm.workspaces (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID        NOT NULL REFERENCES tsm.organizations(id) ON DELETE CASCADE,
    slug           TEXT        NOT NULL,
    display_name   TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_at    TIMESTAMPTZ,
    rate_limit_rpm INT         NOT NULL DEFAULT 200        CHECK (rate_limit_rpm > 0),
    max_body_bytes INT         NOT NULL DEFAULT 4194304,   -- 4 MB
    allowed_models TEXT[]      NOT NULL DEFAULT '{}',      -- empty = all allowed
    metadata       JSONB       NOT NULL DEFAULT '{}',
    UNIQUE (org_id, slug)
);
CREATE INDEX idx_ws_org    ON tsm.workspaces (org_id);
CREATE INDEX idx_ws_active ON tsm.workspaces (org_id) WHERE archived_at IS NULL;
COMMENT ON TABLE tsm.workspaces IS
    'Project-level isolation unit. Each workspace has its own policy, rate limits, and audit trail.';

-- Seed default org + workspace (matches Go control plane in-memory defaults)
INSERT INTO tsm.organizations (id, slug, display_name, plan)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default Organization', 'enterprise')
ON CONFLICT DO NOTHING;

INSERT INTO tsm.workspaces (id, org_id, slug, display_name)
VALUES ('00000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-000000000001',
        'default', 'Default Workspace')
ON CONFLICT DO NOTHING;

-- ── Users ─────────────────────────────────────────────────────────────────────
CREATE TABLE tsm.users (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID        NOT NULL REFERENCES tsm.organizations(id) ON DELETE CASCADE,
    email          TEXT        NOT NULL,
    display_name   TEXT        NOT NULL DEFAULT '',
    -- Password auth (optional; prefer SSO in production)
    password_hash  TEXT,                                   -- bcrypt or argon2id
    -- SSO
    sso_provider   TEXT,                                   -- okta|google|azure
    sso_subject    TEXT,                                   -- external user ID
    -- State
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at  TIMESTAMPTZ,
    deactivated_at TIMESTAMPTZ,
    mfa_enabled    BOOLEAN     NOT NULL DEFAULT FALSE,
    UNIQUE (org_id, email)
);
CREATE INDEX idx_user_email ON tsm.users (email);
CREATE INDEX idx_user_sso   ON tsm.users (sso_provider, sso_subject) WHERE sso_provider IS NOT NULL;
COMMENT ON TABLE tsm.users IS
    'Human operators. Prefer SSO (Okta/Google/Azure) over password auth in production.';

-- ── RBAC roles ────────────────────────────────────────────────────────────────
CREATE TABLE tsm.roles (
    id           UUID  PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID  REFERENCES tsm.organizations(id) ON DELETE CASCADE,  -- NULL = system role
    name         TEXT  NOT NULL,
    description  TEXT  NOT NULL DEFAULT '',
    permissions  TEXT[] NOT NULL DEFAULT '{}',             -- e.g. {policy:read, audit:read}
    system_role  BOOLEAN NOT NULL DEFAULT FALSE,           -- system roles can't be deleted
    UNIQUE (org_id, name)
);

-- System roles (org_id NULL = available to all orgs)
INSERT INTO tsm.roles (id, org_id, name, description, permissions, system_role) VALUES
  ('10000000-0000-0000-0000-000000000001', NULL, 'admin',
   'Full control over org policies, workspaces, and users',
   ARRAY['policy:read','policy:write','audit:read','audit:export',
         'workspace:read','workspace:write','user:read','user:write',
         'node:read','apikey:read','apikey:write','alert:read','alert:write'], TRUE),
  ('10000000-0000-0000-0000-000000000002', NULL, 'security-analyst',
   'Read policies and full audit access; cannot modify policies',
   ARRAY['policy:read','audit:read','audit:export','workspace:read','node:read'], TRUE),
  ('10000000-0000-0000-0000-000000000003', NULL, 'operator',
   'Monitor nodes, view metrics, acknowledge alerts',
   ARRAY['node:read','audit:read','alert:read','alert:ack','workspace:read'], TRUE),
  ('10000000-0000-0000-0000-000000000004', NULL, 'viewer',
   'Read-only access to policies and audit summary',
   ARRAY['policy:read','audit:read','workspace:read'], TRUE)
ON CONFLICT DO NOTHING;

-- Role assignments (user → workspace + role)
CREATE TABLE tsm.role_assignments (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES tsm.users(id) ON DELETE CASCADE,
    workspace_id UUID        REFERENCES tsm.workspaces(id) ON DELETE CASCADE,  -- NULL = org-wide
    role_id      UUID        NOT NULL REFERENCES tsm.roles(id) ON DELETE RESTRICT,
    granted_by   UUID        REFERENCES tsm.users(id),
    granted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,                              -- NULL = permanent
    UNIQUE (user_id, workspace_id, role_id)
);
CREATE INDEX idx_ra_user ON tsm.role_assignments (user_id);
CREATE INDEX idx_ra_ws   ON tsm.role_assignments (workspace_id);

-- ── API keys ──────────────────────────────────────────────────────────────────
-- Keys are 32-byte random, stored as SHA-256(key) — never store plaintext.
-- The prefix (first 8 chars of hex key) is stored for lookup without scanning all hashes.
CREATE TABLE tsm.api_keys (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id   UUID        NOT NULL REFERENCES tsm.workspaces(id) ON DELETE CASCADE,
    created_by     UUID        REFERENCES tsm.users(id),
    name           TEXT        NOT NULL,                   -- human-readable label
    key_prefix     TEXT        NOT NULL,                   -- first 8 hex chars for lookup
    key_hash       TEXT        NOT NULL UNIQUE,            -- SHA-256(raw_key) in hex
    permissions    TEXT[]      NOT NULL DEFAULT ARRAY['proxy:call'],
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at   TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ,
    revoked_at     TIMESTAMPTZ,
    revoke_reason  TEXT,
    rate_limit_rpm INT,                                    -- NULL = inherit workspace limit
    ip_allowlist   INET[]      NOT NULL DEFAULT '{}',      -- empty = all IPs allowed
    CONSTRAINT key_prefix_len CHECK (length(key_prefix) = 8)
);
CREATE INDEX idx_apikey_prefix    ON tsm.api_keys (key_prefix);
CREATE INDEX idx_apikey_workspace ON tsm.api_keys (workspace_id) WHERE revoked_at IS NULL;
COMMENT ON TABLE tsm.api_keys IS
    'API keys issued to services calling the TSM proxy. Raw key shown once at creation; only hash stored.';

-- updated_at auto-maintenance
CREATE OR REPLACE FUNCTION tsm.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END; $$;

CREATE TRIGGER trg_org_updated_at  BEFORE UPDATE ON tsm.organizations
  FOR EACH ROW EXECUTE FUNCTION tsm.set_updated_at();
CREATE TRIGGER trg_ws_updated_at   BEFORE UPDATE ON tsm.workspaces
  FOR EACH ROW EXECUTE FUNCTION tsm.set_updated_at();
