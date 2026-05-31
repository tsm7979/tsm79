# Observability

Three signals: metrics (Prometheus), logs (structured JSON), analytics (ClickHouse). Plus a tamper-evident audit ledger (Postgres) that sits adjacent to all three.

---

## Metrics — Prometheus

Scrape `dataplane:8080/metrics`. Standard exposition format.

### Headline metrics

| Metric | Type | Labels | Notes |
|---|---|---|---|
| `tsm_requests_total` | counter | `provider`, `model`, `verdict` | one per request |
| `tsm_request_duration_seconds` | histogram | `provider`, `verdict` | end-to-end latency including detector hop |
| `tsm_detect_duration_seconds` | histogram | `path` (`fastpath`, `escalated`) | detection-only latency |
| `tsm_pii_types_total` | counter | `pii_type`, `severity` | how often each PII type is detected |
| `tsm_tokens_prompt_total` | counter | `provider`, `model` | exact prompt tokens captured from upstream usage block |
| `tsm_tokens_completion_total` | counter | `provider`, `model` | exact completion tokens |
| `tsm_rate_limit_drops_total` | counter | `client_ip_class` | rate limit rejections |
| `tsm_circuit_breaker_state` | gauge | `upstream` | 0=closed 1=half 2=open |
| `tsm_overlay_resolve_total` | counter | `result` (`cache_hit`, `disk_hit`, `dht_hit`, `not_found`) | sovereign overlay name lookups |
| `tsm_overlay_records_rejected_total` | counter | `reason` (`bad_sig`, `hijack`, `replay`, `clock_skew`, `expired`) | anti-hijack telemetry |
| `tsm_audit_chain_verify_failures_total` | counter | — | should always be 0; non-zero means tamper |

### Recording rules

In `observability/prometheus/recording-rules.yml`:

```yaml
groups:
  - name: tsm.rates
    interval: 30s
    rules:
      - record: tsm:rps
        expr: sum(rate(tsm_requests_total[1m]))

      - record: tsm:rps_by_verdict
        expr: sum by (verdict) (rate(tsm_requests_total[1m]))

      - record: tsm:p50_latency
        expr: histogram_quantile(0.5, sum(rate(tsm_request_duration_seconds_bucket[5m])) by (le))

      - record: tsm:p99_latency
        expr: histogram_quantile(0.99, sum(rate(tsm_request_duration_seconds_bucket[5m])) by (le))

      - record: tsm:block_rate
        expr: sum(rate(tsm_requests_total{verdict="block"}[5m])) / sum(rate(tsm_requests_total[5m]))
```

### Alerts

In `observability/prometheus/alerts.yml`:

```yaml
groups:
  - name: tsm.critical
    rules:
      - alert: TSMHighBlockRate
        expr: tsm:block_rate > 0.1
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Block rate > 10% — investigate"

      - alert: TSMCircuitOpen
        expr: tsm_circuit_breaker_state == 2
        for: 1m
        labels: { severity: critical }

      - alert: TSMAuditChainTamper
        expr: increase(tsm_audit_chain_verify_failures_total[5m]) > 0
        labels: { severity: critical }
        annotations:
          summary: "Audit ledger tamper detected — escalate"

      - alert: TSMOverlayHijackAttempt
        expr: increase(tsm_overlay_records_rejected_total{reason="hijack"}[5m]) > 10
        labels: { severity: warning }
```

---

## Logs — structured JSON

All services log JSON to stdout. Recommended pipeline: Vector → Loki → Grafana.

Standard fields:

```json
{
  "ts":        "2026-05-30T22:15:03.421Z",
  "level":     "info",
  "service":   "dataplane",
  "trace_id":  "8d4a1c20…",
  "span_id":   "8a3b…",
  "request_id":"r_01H…",
  "client_ip": "10.0.1.42",
  "provider":  "openai",
  "model":     "gpt-4o-mini",
  "verdict":   "redact",
  "pii_types": ["EMAIL", "PHONE"],
  "latency_ms": 12.4,
  "msg":       "request scanned, redacted, forwarded"
}
```

Never log request bodies or response bodies at `info` or above. Body sampling is gated behind `TSM_DEBUG_SAMPLE_RATE` (default 0) and goes to a separate stream marked `sensitive: true`.

---

## Analytics — ClickHouse

Schema: `observability/clickhouse/schema.sql`. The dataplane batches rows and sends them via JSONEachRow.

### `tsm.ai_requests`

```sql
CREATE TABLE tsm.ai_requests
(
    ts              DateTime64(3),
    request_id      String,
    workspace_id    String,
    client_ip       IPv4,
    original_dst_ip IPv4,
    provider        LowCardinality(String),
    model           LowCardinality(String),
    endpoint        LowCardinality(String),
    verdict         LowCardinality(String),
    pii_types       Array(LowCardinality(String)),
    severity        LowCardinality(String),
    risk_score      UInt8,
    latency_us      UInt32,
    upstream_status UInt16,
    prompt_tokens   UInt32,
    completion_tokens UInt32,
    rule_id         LowCardinality(String),
    detector_path   LowCardinality(String)   -- fastpath | escalated | quarantine
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (workspace_id, ts);
```

### Useful queries

Top blocking rules over 24h:

```sql
SELECT rule_id, count() AS blocks
FROM tsm.ai_requests
WHERE ts > now() - INTERVAL 24 HOUR AND verdict = 'block'
GROUP BY rule_id
ORDER BY blocks DESC
LIMIT 20;
```

Workspace-by-workspace verdict mix:

```sql
SELECT
    workspace_id,
    verdict,
    count() AS n,
    round(100 * count() / sum(count()) OVER (PARTITION BY workspace_id), 2) AS pct
FROM tsm.ai_requests
WHERE ts > now() - INTERVAL 1 HOUR
GROUP BY workspace_id, verdict
ORDER BY workspace_id, pct DESC;
```

Token consumption per workspace:

```sql
SELECT
    workspace_id,
    provider,
    sum(prompt_tokens) AS prompt,
    sum(completion_tokens) AS completion,
    sum(prompt_tokens + completion_tokens) AS total
FROM tsm.ai_requests
WHERE ts > now() - INTERVAL 1 DAY
GROUP BY workspace_id, provider
ORDER BY total DESC;
```

### Ingestor — gotchas (post-#32)

Two long-standing bugs in `observability/clickhouse/ingestor.rs` were fixed in v3.0.0. If you maintain a fork, retain these fixes:

1. `http_post` previously left `user:password@` userinfo inline in the URL authority. Now it `rsplit_once('@')` separates it and sends `X-ClickHouse-User` / `X-ClickHouse-Key` headers.
2. Empty `client_ip` / `original_dst_ip` strings into `IPv4` columns previously produced `400 Cannot parse IPv4`. Now `ipv4_or_zero()` coerces empty → `0.0.0.0`.

Verify ingestion is working:

```sql
SELECT count() FROM tsm.ai_requests WHERE ts > now() - INTERVAL 1 MINUTE;
```

If 0 after sustained traffic, check the dataplane logs for `clickhouse_ingest_error`.

---

## Audit ledger — Postgres

Tamper-evident, append-only, Merkle-chained. Schema: `deploy/postgres/migrations/V004__audit_log.sql`.

### `audit_log`

```sql
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_id  TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    pii_types   TEXT[] NOT NULL,
    severity    TEXT NOT NULL,
    rule_id     TEXT,
    prev_hash   BYTEA NOT NULL,
    entry_hash  BYTEA NOT NULL,
    metadata    JSONB
);

CREATE INDEX audit_log_ts ON audit_log (ts DESC);
CREATE INDEX audit_log_workspace_ts ON audit_log (workspace_id, ts DESC);
CREATE INDEX audit_log_pii_types ON audit_log USING GIN (pii_types);
```

Each `entry_hash` is `HMAC_SHA256(prev_hash || canonical_row_bytes)`. Verify the chain:

```bash
tsm audit verify --since 24h
# OK: 184,932 entries verified, no tamper detected
```

If verification fails, the `tsm_audit_chain_verify_failures_total` counter increments and the `TSMAuditChainTamper` alert fires.

---

## Tracing — OpenTelemetry

The dataplane emits OTLP-compatible spans. Configure:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
export OTEL_SERVICE_NAME=tsm-dataplane
export OTEL_RESOURCE_ATTRIBUTES=service.namespace=ai-control-plane,deployment.environment=prod
```

Span names follow the convention `<component>.<op>`:

- `dataplane.handle_request`
- `detect.fastpath`
- `detect.escalate_grpc`
- `policy.evaluate`
- `audit.append`
- `overlay.resolve`
- `overlay.gateway_fetch`

Custom span attributes include `tsm.verdict`, `tsm.pii_types`, `tsm.workspace_id`, `tsm.rule_id`.

---

## Dashboards

Pre-built Grafana dashboards in `observability/grafana/dashboards/`:

| Dashboard | Audience |
|---|---|
| `dataplane-ops.json` | SRE — request rate, verdict mix, latency, circuit state |
| `detection-quality.json` | Security — PII type frequency, escalation rate, quarantine queue depth |
| `business.json` | Product — workspace token consumption, model mix, rule-effectiveness |
| `overlay-health.json` | Overlay operator — DHT peer count, record propagation latency, hijack rejections |

Import via `grafana-cli plugins install` then upload the JSON in the Grafana UI.

---

## Health checks

Each service exposes `/health` (200 if healthy, 503 if not):

- `dataplane:8080/health` — checks detector connectivity, Redis, Postgres, ClickHouse
- `detector-grpc` — gRPC health-check (`grpc.health.v1`)
- `admin-api:8088/actuator/health` — Spring Boot Actuator
- `overlay-node:9001/health` — DHT peer count, libp2p listener state

Compose healthchecks already wire these up. For Kubernetes, use `livenessProbe` and `readinessProbe` on the same paths.
