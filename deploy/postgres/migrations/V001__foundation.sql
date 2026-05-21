-- ============================================================================
-- V001 — Foundation: extensions, schema, migration tracking
-- Compatible with: Flyway 9+, golang-migrate, liquibase
-- PostgreSQL >= 15 required (gen_random_uuid, pg_stat_statements)
-- ============================================================================

-- Core extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";          -- uuid_generate_v4()
CREATE EXTENSION IF NOT EXISTS "pgcrypto";           -- gen_random_bytes, crypt
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements"; -- query telemetry
CREATE EXTENSION IF NOT EXISTS "pg_trgm";            -- trigram indexes for search
CREATE EXTENSION IF NOT EXISTS "btree_gin";          -- composite GIN indexes

-- Application schema (isolates TSM objects from public)
CREATE SCHEMA IF NOT EXISTS tsm;
SET search_path TO tsm, public;

-- ── Schema version tracking (managed by migration tool) ──────────────────────
-- This table is the source of truth for applied migrations.
-- The migration runner inserts a row per file; rollbacks delete it.
CREATE TABLE IF NOT EXISTS tsm.schema_migrations (
    version        TEXT        NOT NULL PRIMARY KEY,   -- e.g. "V001"
    description    TEXT        NOT NULL,
    applied_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_by     TEXT        NOT NULL DEFAULT current_user,
    checksum       TEXT,                               -- SHA-256 of migration file
    execution_ms   INT
);

COMMENT ON TABLE tsm.schema_migrations IS
    'Flyway-compatible migration ledger. Do not modify manually.';
