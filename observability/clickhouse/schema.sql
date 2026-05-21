-- ClickHouse schema for TSM AI Firewall observability.
--
-- Why ClickHouse (not PostgreSQL):
--   PostgreSQL: ~50K inserts/sec, row-oriented, B-tree indexes
--   ClickHouse: ~1M inserts/sec, columnar, sorted merge trees, 10-50x compression
--
-- 100M events/day → 1157 events/sec average, 50K/sec burst.
-- PostgreSQL can't sustain that with ACID writes. ClickHouse handles it trivially.
--
-- Retention: 90 days hot (MergeTree), 1 year cold (TTL MOVE to S3 tier).
--
-- Setup:
--   clickhouse-client --multiquery < schema.sql
--
-- Query example:
--   SELECT pii_types, count() AS cnt, avg(risk_score) AS avg_risk
--   FROM tsm.ai_requests
--   WHERE timestamp >= now() - INTERVAL 1 HOUR
--   GROUP BY pii_types ORDER BY cnt DESC LIMIT 20;

CREATE DATABASE IF NOT EXISTS tsm;

-- ── Main request event table ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tsm.ai_requests
(
    -- Time (partition key — ClickHouse stores per-day directories)
    timestamp           DateTime64(3, 'UTC')   NOT NULL,
    date                Date                   MATERIALIZED toDate(timestamp),

    -- Identity
    request_id          String,
    session_id          String,
    org_id              String,
    workspace_id        String,
    node_id             String,  -- which TSM node handled this

    -- Request metadata
    model               LowCardinality(String),     -- gpt-4, claude-3-opus, etc.
    provider            LowCardinality(String),     -- openai, anthropic, gemini
    endpoint            LowCardinality(String),     -- /v1/chat/completions
    method              LowCardinality(String),     -- POST

    -- Client info
    client_ip           IPv4,
    client_asn          UInt32,
    client_country      LowCardinality(FixedString(2)),
    ja3_hash            FixedString(32),
    ja4                 String,
    is_tor              UInt8,
    is_vpn              UInt8,

    -- Detection
    action              LowCardinality(String),     -- allow, block, redact, route_local
    pii_types           Array(LowCardinality(String)),
    risk_score          Float32,
    severity            LowCardinality(String),     -- low, medium, high, critical
    policy_rule         String,
    detection_stage     LowCardinality(String),     -- tier0, tier1, tier2, regex, bpe
    detection_latency_us UInt32,                    -- microseconds

    -- TLS / Network
    tls_version         LowCardinality(String),
    original_dst_ip     IPv4,
    original_dst_port   UInt16,
    route_pin           LowCardinality(String),     -- local, cloud, unset
    session_sensitive   UInt8,

    -- Payload sizes
    request_bytes       UInt32,
    response_bytes      UInt32,

    -- Timing
    total_latency_ms    UInt32,
    upstream_latency_ms UInt32,

    -- Output inspection (post-response scan)
    output_clean        UInt8,
    output_threat_type  LowCardinality(String),

    -- Threat intelligence
    threat_intel_score  Float32,
    ioc_match           UInt8,

    -- Audit
    merkle_epoch        UInt32,
    merkle_leaf_index   UInt32,

    -- Circuit breaker
    circuit_state       LowCardinality(String)  -- closed, open, half-open

) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (org_id, timestamp, session_id)
TTL date + INTERVAL 90 DAY
    DELETE,
    date + INTERVAL 30 DAY
    TO DISK 'cold'
SETTINGS
    index_granularity = 8192,
    merge_with_ttl_timeout = 3600;

-- ── Materialized view: per-org per-hour summary ───────────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS tsm.hourly_org_summary
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (org_id, hour, action)
AS
SELECT
    org_id,
    toStartOfHour(timestamp) AS hour,
    action,
    count()                  AS requests,
    sum(request_bytes)       AS total_request_bytes,
    avg(risk_score)          AS avg_risk,
    sum(if(ioc_match, 1, 0)) AS ioc_hits,
    avg(total_latency_ms)    AS avg_latency_ms,
    quantile(0.99)(total_latency_ms) AS p99_latency_ms
FROM tsm.ai_requests
GROUP BY org_id, hour, action;

-- ── Materialized view: JA3 threat summary ─────────────────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS tsm.ja3_threat_summary
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, ja3_hash)
AS
SELECT
    date,
    ja3_hash,
    count()          AS requests,
    uniq(client_ip)  AS unique_ips,
    uniq(org_id)     AS unique_orgs,
    avg(risk_score)  AS avg_risk
FROM tsm.ai_requests
WHERE ja3_hash != ''
GROUP BY date, ja3_hash;

-- ── Materialized view: PII type frequency ─────────────────────────────────────

CREATE MATERIALIZED VIEW IF NOT EXISTS tsm.pii_type_counts
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, pii_type)
AS
SELECT
    date,
    pii_type,
    count() AS occurrences,
    uniq(org_id) AS orgs_affected
FROM tsm.ai_requests
ARRAY JOIN pii_types AS pii_type
WHERE length(pii_types) > 0
GROUP BY date, pii_type;

-- ── Materialized view: XDP packet counters ────────────────────────────────────

CREATE TABLE IF NOT EXISTS tsm.xdp_packet_events
(
    timestamp       DateTime64(3, 'UTC') NOT NULL,
    date            Date MATERIALIZED toDate(timestamp),
    node_id         String,
    src_ip          IPv4,
    dst_ip          IPv4,
    action          LowCardinality(String),  -- drop_rate, drop_syn, drop_blocklist, pass
    packets         UInt64,
    bytes           UInt64
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (node_id, timestamp)
TTL date + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

-- ── Threat intelligence events ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tsm.threat_intel_events
(
    timestamp       DateTime64(3, 'UTC') NOT NULL,
    date            Date MATERIALIZED toDate(timestamp),
    feed_name       LowCardinality(String),  -- nvd_cve, cisa_kev, abuseipdb, etc.
    indicator_type  LowCardinality(String),  -- ip, domain, hash, cve
    indicator       String,
    threat_score    Float32,
    ttl_hours       UInt16,
    metadata        String   -- JSON blob for feed-specific fields
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (feed_name, timestamp)
TTL date + INTERVAL 30 DAY DELETE;

-- ── Merkle audit chain (epoch roots for compliance pinning) ───────────────────

CREATE TABLE IF NOT EXISTS tsm.merkle_epochs
(
    sealed_at       DateTime64(3, 'UTC') NOT NULL,
    node_id         String,
    epoch_index     UInt64,
    event_count     UInt32,
    epoch_root_hex  FixedString(64),     -- SHA-256 hex
    prev_root_hex   FixedString(64),
    chain_root_hex  FixedString(64)      -- chained (epoch_root ‖ prev_root)
) ENGINE = ReplacingMergeTree(sealed_at)
ORDER BY (node_id, epoch_index);

-- ── Circuit breaker state log ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tsm.circuit_breaker_events
(
    timestamp       DateTime64(3, 'UTC') NOT NULL,
    node_id         String,
    upstream        LowCardinality(String),
    from_state      LowCardinality(String),
    to_state        LowCardinality(String),
    reason          String
) ENGINE = MergeTree()
ORDER BY (node_id, timestamp)
TTL toDate(timestamp) + INTERVAL 30 DAY DELETE;

-- ── Useful query shortcuts ────────────────────────────────────────────────────
-- (Save as views for Grafana integration)

CREATE VIEW IF NOT EXISTS tsm.v_blocked_last_hour AS
SELECT
    timestamp,
    org_id,
    client_ip,
    pii_types,
    risk_score,
    policy_rule,
    ja3_hash,
    total_latency_ms
FROM tsm.ai_requests
WHERE timestamp >= now() - INTERVAL 1 HOUR
  AND action = 'block'
ORDER BY risk_score DESC
LIMIT 1000;

CREATE VIEW IF NOT EXISTS tsm.v_top_threat_orgs AS
SELECT
    org_id,
    count()          AS total_requests,
    countIf(action = 'block') AS blocked,
    avg(risk_score)  AS avg_risk,
    max(risk_score)  AS max_risk
FROM tsm.ai_requests
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY org_id
ORDER BY blocked DESC
LIMIT 50;

CREATE VIEW IF NOT EXISTS tsm.v_latency_percentiles AS
SELECT
    toStartOfMinute(timestamp) AS minute,
    quantile(0.50)(total_latency_ms) AS p50,
    quantile(0.95)(total_latency_ms) AS p95,
    quantile(0.99)(total_latency_ms) AS p99,
    count() AS requests
FROM tsm.ai_requests
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY minute
ORDER BY minute;
