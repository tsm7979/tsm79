// Package db provides a thin PostgreSQL persistence layer for the TSM control plane.
//
// It uses database/sql + lib/pq (stdlib-compatible driver) — no ORM, no code generation.
//
// Two concerns:
//   1. PolicyPersistence — durable snapshot storage; survives control-plane restarts.
//   2. NodePersistence   — durable node registry; syncs in-memory cluster.Registry to DB.
//
// Both are optional: if TSM_PG_DSN is unset the control plane runs fully in-memory
// (as it did before) and these packages are no-ops.
package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/lib/pq" // Register "postgres" driver
)

// DB is the shared database handle.  It is a thin wrapper around *sql.DB
// with a connection-pool pre-configured for the control plane's modest load.
type DB struct {
	pool *sql.DB
}

// Open opens a connection pool from the DSN.
// DSN format: "host=localhost port=5432 dbname=tsm user=tsm password=... sslmode=require"
// Or: postgres://user:pass@host:5432/dbname?sslmode=require
func Open(dsn string) (*DB, error) {
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("db.Open: %w", err)
	}

	pool.SetMaxOpenConns(10)
	pool.SetMaxIdleConns(4)
	pool.SetConnMaxLifetime(30 * time.Minute)
	pool.SetConnMaxIdleTime(5 * time.Minute)

	if err := pool.Ping(); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("db.Open: ping failed: %w", err)
	}

	slog.Info("database connection pool established", "dsn_prefix", redactDSN(dsn))
	return &DB{pool: pool}, nil
}

// OpenFromEnv opens a connection from the TSM_PG_DSN environment variable.
// Returns (nil, nil) if the variable is not set (no-op mode).
func OpenFromEnv() (*DB, error) {
	dsn := os.Getenv("TSM_PG_DSN")
	if dsn == "" {
		return nil, nil // no-op — in-memory mode
	}
	return Open(dsn)
}

// Close shuts down the connection pool.
func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	return d.pool.Close()
}

// Pool returns the underlying *sql.DB for advanced use.
func (d *DB) Pool() *sql.DB { return d.pool }

// ── Policy Persistence ─────────────────────────────────────────────────────────

// PolicyPersistence wraps DB with policy-specific queries.
type PolicyPersistence struct{ db *DB }

// NewPolicyPersistence creates a PolicyPersistence.  If db is nil, all methods are no-ops.
func NewPolicyPersistence(db *DB) *PolicyPersistence {
	return &PolicyPersistence{db: db}
}

// LoadLatest loads the highest-versioned policy snapshot from tsm.policy_snapshots.
// Returns (nil, nil) if no snapshots exist.
func (p *PolicyPersistence) LoadLatest(workspaceID string) (rulesJSON []byte, version int64, err error) {
	if p.db == nil {
		return nil, 0, nil
	}

	var rj string
	err = p.db.pool.QueryRow(`
		SELECT rules_json, version
		FROM tsm.policy_snapshots
		WHERE workspace_id = $1
		ORDER BY version DESC
		LIMIT 1`, workspaceID).Scan(&rj, &version)

	if err == sql.ErrNoRows {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("PolicyPersistence.LoadLatest: %w", err)
	}
	return []byte(rj), version, nil
}

// SaveSnapshot persists a new policy snapshot.
// version must be monotonically increasing; the DB enforces UNIQUE(version).
func (p *PolicyPersistence) SaveSnapshot(workspaceID string, version int64, rules any, createdByUserID string) error {
	if p.db == nil {
		return nil
	}

	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("PolicyPersistence.SaveSnapshot: marshal: %w", err)
	}

	_, err = p.db.pool.Exec(`
		INSERT INTO tsm.policy_snapshots (workspace_id, version, rules_json, created_by)
		VALUES ($1, $2, $3, $4::uuid)
		ON CONFLICT (version) DO NOTHING`,
		workspaceID, version, string(rulesJSON), nilIfEmpty(createdByUserID))

	if err != nil {
		return fmt.Errorf("PolicyPersistence.SaveSnapshot: insert: %w", err)
	}
	return nil
}

// ── Node Persistence ───────────────────────────────────────────────────────────

// NodeRecord mirrors tsm.nodes columns relevant to the Go registry.
type NodeRecord struct {
	ID              string
	OrgID           string
	Role            string // dataplane | detector | control-plane
	Addr            string
	HealthPath      string
	Healthy         bool
	ConsecutiveFails int
	PolicyVersion   int64
	VersionString   string
	Region          string
	Zone            string
	Labels          map[string]string
	LastSeenAt      time.Time
}

// NodePersistence wraps DB with node-registry queries.
type NodePersistence struct{ db *DB }

func NewNodePersistence(db *DB) *NodePersistence { return &NodePersistence{db: db} }

// Upsert registers or updates a node.  Called by dataplane nodes on startup
// and by the control plane's health-check loop.
func (n *NodePersistence) Upsert(r *NodeRecord) error {
	if n.db == nil {
		return nil
	}

	labelsJSON, err := json.Marshal(r.Labels)
	if err != nil {
		labelsJSON = []byte("{}")
	}

	_, err = n.db.pool.Exec(`
		INSERT INTO tsm.nodes
			(id, org_id, role, addr, health_path, healthy, consecutive_fails,
			 policy_version, version_string, region, zone, labels, last_seen_at)
		VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, NOW())
		ON CONFLICT (id) DO UPDATE SET
			addr              = EXCLUDED.addr,
			healthy           = EXCLUDED.healthy,
			consecutive_fails = EXCLUDED.consecutive_fails,
			policy_version    = EXCLUDED.policy_version,
			version_string    = EXCLUDED.version_string,
			labels            = EXCLUDED.labels,
			last_seen_at      = NOW()`,
		r.ID, r.OrgID, r.Role, r.Addr, r.HealthPath,
		r.Healthy, r.ConsecutiveFails,
		r.PolicyVersion, r.VersionString,
		r.Region, r.Zone, string(labelsJSON))

	if err != nil {
		return fmt.Errorf("NodePersistence.Upsert: %w", err)
	}
	return nil
}

// ListHealthy returns all healthy nodes for an org, sorted by role and ID.
func (n *NodePersistence) ListHealthy(orgID string) ([]*NodeRecord, error) {
	if n.db == nil {
		return nil, nil
	}

	rows, err := n.db.pool.Query(`
		SELECT id, org_id, role, addr, health_path, healthy, consecutive_fails,
		       policy_version, version_string, region, COALESCE(zone,''), labels, last_seen_at
		FROM tsm.nodes
		WHERE org_id = $1::uuid AND healthy = TRUE
		ORDER BY role, id`, orgID)
	if err != nil {
		return nil, fmt.Errorf("NodePersistence.ListHealthy: %w", err)
	}
	defer rows.Close()

	var nodes []*NodeRecord
	for rows.Next() {
		r := &NodeRecord{}
		var labelsJSON string
		if err := rows.Scan(
			&r.ID, &r.OrgID, &r.Role, &r.Addr, &r.HealthPath,
			&r.Healthy, &r.ConsecutiveFails,
			&r.PolicyVersion, &r.VersionString,
			&r.Region, &r.Zone, &labelsJSON, &r.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("NodePersistence.ListHealthy: scan: %w", err)
		}
		_ = json.Unmarshal([]byte(labelsJSON), &r.Labels)
		nodes = append(nodes, r)
	}
	return nodes, rows.Err()
}

// MarkUnhealthy sets consecutive_fails and clears healthy for a node.
func (n *NodePersistence) MarkUnhealthy(nodeID string, fails int) error {
	if n.db == nil {
		return nil
	}
	_, err := n.db.pool.Exec(`
		UPDATE tsm.nodes
		SET healthy = FALSE, consecutive_fails = $2
		WHERE id = $1`, nodeID, fails)
	return err
}

// UpdatePolicyVersion records the policy version a node has acknowledged.
func (n *NodePersistence) UpdatePolicyVersion(nodeID string, version int64) error {
	if n.db == nil {
		return nil
	}
	_, err := n.db.pool.Exec(`
		UPDATE tsm.nodes
		SET policy_version = $2, last_seen_at = NOW()
		WHERE id = $1`, nodeID, version)
	return err
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// redactDSN removes the password from a DSN string for safe logging.
func redactDSN(dsn string) string {
	if len(dsn) > 40 {
		return dsn[:20] + "...<redacted>"
	}
	return dsn[:len(dsn)/2] + "...<redacted>"
}
