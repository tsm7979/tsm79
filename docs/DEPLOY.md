# Deploy Guide

Production deployment guide for the TSM79 enterprise stack.

This document covers the canonical compose deployment. For Kubernetes, see the Helm chart in `deploy/helm/` (when published). The operator dashboard and public landing live in companion repositories.

---

## Sizing — start here

| Tier | Load | Hosts | Profile |
|---|---|---|---|
| **Lab** | < 10 rps | 1 | 2 vCPU, 4 GB RAM, 20 GB SSD — runs everything in a single compose stack |
| **Small** | 10–500 rps | 1 | 8 vCPU, 16 GB RAM, 100 GB NVMe — single host, all services |
| **Medium** | 500–5,000 rps | 3 | dataplane on dedicated host; detector + observability co-resident; admin-api + Postgres on the third |
| **Large** | > 5,000 rps | 6+ | per-component pools, ClickHouse cluster, Postgres replicated |

Dataplane is the only hot-path component. Scale it horizontally first.

---

## Compose — canonical stack

```bash
git clone https://github.com/tsm7979/tsm79.git
cd tsm79
cp .env.example .env
$EDITOR .env       # set CLICKHOUSE_PASSWORD, provider keys, etc.
docker compose -f docker-compose.enterprise.yml up -d
```

Eleven services come up:

| Service | Port | Purpose |
|---|---|---|
| `dataplane` | `:8080`, `:8443` | OpenAI-compatible proxy + Prometheus `/metrics` + overlay gateway |
| `detector-grpc` | `:50051` | Python ML detector — gRPC escalation target |
| `control-plane` | `:8089` | Go — workspace + key store |
| `threat-intel` | `:8090` | Go — IP reputation feeds |
| `admin-api` | `:8088` | Java Spring Boot — operator REST control |
| `policy-lsp` | (unix socket) | C# .NET — policy DSL language server for editors |
| `postgres` | `:5432` | Audit ledger + Merkle chain + workspace store |
| `clickhouse` | `:8123`, `:9000` | Analytics ingest |
| `redis` | `:6379` | Rate limit + session pinning |
| `overlay-node` | `:9001` | libp2p Kademlia DHT under `/tsm` |

All services have healthchecks. `docker compose ps` reaches `Up (healthy)` within ~60s on a warm machine.

---

## TLS / mTLS

`deploy/nginx/conf.d/mtls.conf` provides an nginx fronting the admin-api with mTLS. Generate the operator CA and a client cert:

```bash
mkdir -p deploy/nginx/certs && cd deploy/nginx/certs

# CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -days 3650 -out ca.crt -subj "/CN=TSM-Operator-CA"

# Server cert (matches the admin nginx hostname)
openssl genrsa -out admin.key 4096
openssl req -new -key admin.key -out admin.csr -subj "/CN=admin.tsm.local"
openssl x509 -req -in admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out admin.crt

# Client cert (one per operator)
openssl genrsa -out operator-alice.key 4096
openssl req -new -key operator-alice.key -out operator-alice.csr -subj "/CN=alice"
openssl x509 -req -in operator-alice.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out operator-alice.crt
openssl pkcs12 -export -in operator-alice.crt -inkey operator-alice.key -out operator-alice.p12
```

Distribute `operator-alice.p12` to the operator. They import it into their browser keychain.

---

## Secret rotation

| Secret | Where stored | How to rotate |
|---|---|---|
| Provider API keys (OpenAI, Anthropic, etc.) | `.env` → mounted into `dataplane` | Update `.env` and `docker compose up -d` — dataplane picks up the new key on the next container start; existing in-flight requests drain |
| `CLICKHOUSE_PASSWORD` | `.env` → both ClickHouse and the ingestor | Update `.env`, then on ClickHouse: `ALTER USER tsm IDENTIFIED BY 'new-password'`; restart `dataplane` so the ingestor picks up the new password |
| Postgres credentials | `.env` → `postgres` and `admin-api`, `dataplane` | `ALTER USER tsm WITH PASSWORD 'new-password'`; update `.env`; restart consumers |
| Admin API workspace keys | Postgres `workspaces` table | Use `POST /workspaces/{id}/rotate-key` on `admin-api` |
| mTLS operator certs | `deploy/nginx/certs/` | Issue a new client cert from the CA; revoke the old one by adding its serial to the nginx `ssl_crl` list and reloading nginx |
| Sovereign-overlay name keys | `~/.tsm/overlay/<name>.key` (operator-managed) | `tsm overlay rotate --key <key>` — publishes a new `NameRecord` with the new `pubkey`, but operators who have cached the old `pubkey` will REJECT this (anti-hijack). Plan key rotation as a name retirement + new name issuance |

---

## Backups

| What | How often | Where |
|---|---|---|
| Postgres (audit + workspaces) | Hourly WAL + daily base backup | Encrypted S3 bucket; ≥ 90-day retention |
| ClickHouse (analytics) | Daily | Replication to a cold ClickHouse, or `clickhouse-backup` to encrypted S3 |
| Sovereign-overlay name keys | On key generation + on every rotation | Operator-managed; do NOT centralize. Recommend Shamir-shared backup |
| Policy bundles | Per commit | Already in git |
| `.env` | Per change | Operator-managed; do NOT commit |

---

## Observability

| Signal | Target |
|---|---|
| Metrics | Prometheus scrapes `dataplane:8080/metrics` |
| Logs | structured JSON to stdout; ship via Vector / Loki / your aggregator |
| Traces | OpenTelemetry-compatible; OTLP exporter to your collector |
| Audit | Postgres `audit_log` — Merkle-chained, verify with `tsm audit verify --since 24h` |
| Analytics | ClickHouse `tsm.ai_requests` — rows landing on every request, see [OBSERVABILITY.md](OBSERVABILITY.md) |

---

## Upgrade

Conservative — no in-flight request loss:

```bash
git fetch
git checkout v3.x.y                              # pin a release tag
docker compose -f docker-compose.enterprise.yml pull
docker compose -f docker-compose.enterprise.yml up -d --no-deps --build dataplane
# Wait for dataplane health to recover, then iterate per-service.
```

Aggressive — all-at-once, brief downtime:

```bash
docker compose -f docker-compose.enterprise.yml down
git checkout v3.x.y
docker compose -f docker-compose.enterprise.yml up -d
```

Audit-ledger migrations are applied automatically on `admin-api` startup. Postgres migrations are versioned in `deploy/postgres/migrations/V*.sql` and applied with `flyway` from inside the `admin-api` container.

---

## Disaster recovery

| Failure | Recovery |
|---|---|
| Dataplane crash | Compose restarts; rate-limit state warms back from Redis; circuit-breaker state starts CLOSED |
| Detector crash | Dataplane fail-secure: requests that would have escalated are dropped at `quarantine` until the detector returns |
| Postgres loss | Restore from latest base + replay WAL; audit chain verifies via `tsm audit verify` to detect tamper |
| ClickHouse loss | Replay from the dataplane's local JSONL buffer (default 24h) once ClickHouse is back |
| Sovereign-overlay node loss | A new node joins the DHT, fetches records on demand; records continue propagating from other nodes |
| Operator key loss | Plan for this. Use Shamir-shared backups |

---

## Hardening checklist (pre-production)

- [ ] mTLS on admin-api (the nginx in `deploy/nginx/conf.d/mtls.conf`)
- [ ] `CLICKHOUSE_PASSWORD` rotated from default
- [ ] Postgres password rotated from default
- [ ] Provider API keys least-privileged (separate keys per workspace if your provider supports it)
- [ ] Rate limits sized to your expected load
- [ ] Circuit breaker thresholds reviewed
- [ ] Audit-ledger verification cron set up (`tsm audit verify --since 1h` every hour)
- [ ] Backup pipeline tested by restore
- [ ] Detector model checkpoints pinned (don't auto-update at runtime)
- [ ] All container images digest-pinned (not `latest`)
- [ ] Workspace API keys distributed via secret-manager, not in chat
- [ ] No `:8080` exposed to the public internet (front with mTLS or your gateway)

---

## Contact

For sovereign deployments (air-gapped, on-prem, BGP-anycast PoPs, hosted control plane), contact <founder@thesovereignmechanica.ai>.
