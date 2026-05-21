// TSM Control Plane — cluster coordination, policy distribution, health federation.
//
// Architecture:
//
//   ┌─────────────────────────────────────────────────────┐
//   │              TSM Control Plane (Go)                 │
//   │                                                     │
//   │  POST /nodes/register  ← dataplane, proxy, detector │
//   │  GET  /config/policy   → versioned ruleset (ETag)   │
//   │  PUT  /config/policy   ← admin hot-reload           │
//   │  GET  /nodes           → cluster health map         │
//   │  GET  /metrics         → Prometheus scrape          │
//   └─────────────────────────────────────────────────────┘
//
// Every dataplane node registers on startup and polls GET /config/policy with
// If-None-Match: <version>.  The control plane responds 304 (no change) or
// 200 with the new ruleset JSON.  Nodes ACK with PUT /nodes/{id}/policy-ack.
//
// The background health poller probes registered nodes every 10 seconds.
// Nodes that miss 3 consecutive checks are marked unhealthy and excluded from
// the /nodes?role=dataplane&healthy=true response used by the load balancer.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/tsm7979/tsm/control-plane/api"
	"github.com/tsm7979/tsm/control-plane/cluster"
	"github.com/tsm7979/tsm/control-plane/db"
	"github.com/tsm7979/tsm/control-plane/policy"
	"github.com/tsm7979/tsm/control-plane/queue"
	"github.com/tsm7979/tsm/control-plane/suggestion"
)

func main() {
	// ── Configuration from environment ────────────────────────────────────────
	port         := envOr("TSM_CP_PORT",         "9090")
	logLevel     := envOr("TSM_CP_LOG_LEVEL",    "info")
	pollInterval := envDuration("TSM_CP_HEALTH_INTERVAL", 10*time.Second)

	// ── Structured logger ─────────────────────────────────────────────────────
	level := slog.LevelInfo
	if logLevel == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	slog.Info("TSM Control Plane starting",
		"port", port,
		"health_poll_interval", pollInterval.String(),
	)

	// ── PostgreSQL persistence (optional — runs in-memory if TSM_PG_DSN unset) ─
	database, dbErr := db.OpenFromEnv()
	if dbErr != nil {
		slog.Warn("database connection failed — running in-memory only", "err", dbErr)
		database = nil
	} else if database != nil {
		slog.Info("database connected")
		defer database.Close()
	} else {
		slog.Info("TSM_PG_DSN not set — running in-memory only")
	}
	policyDB := db.NewPolicyPersistence(database)
	nodeDB   := db.NewNodePersistence(database)

	// ── Core subsystems ───────────────────────────────────────────────────────
	policyStore := policy.NewStore()
	registry    := cluster.NewRegistry()

	// Restore last persisted policy snapshot from PostgreSQL
	defaultOrgWorkspace := envOr("TSM_DEFAULT_WORKSPACE_ID", "00000000-0000-0000-0000-000000000002")
	if rulesJSON, version, err := policyDB.LoadLatest(defaultOrgWorkspace); err != nil {
		slog.Warn("could not load persisted policy — using built-in defaults", "err", err)
	} else if rulesJSON != nil {
		var rules []policy.Rule
		if err := json.Unmarshal(rulesJSON, &rules); err == nil {
			snap := policyStore.Put(rules)
			_ = snap
			slog.Info("restored policy from database", "version", version, "rules", len(rules))
		}
	}

	// Hook: persist new snapshots to PostgreSQL whenever Put() is called
	policyStore.OnPut(func(snap *policy.Snapshot) {
		if err := policyDB.SaveSnapshot(
			defaultOrgWorkspace, snap.Version, snap.Rules, "",
		); err != nil {
			slog.Warn("failed to persist policy snapshot", "version", snap.Version, "err", err)
		}
	})

	// Hook: sync node state to PostgreSQL on registry updates
	registry.OnNodeUpdate(func(n *cluster.Node) {
		rec := &db.NodeRecord{
			ID:               n.ID,
			OrgID:            envOr("TSM_DEFAULT_ORG_ID", "00000000-0000-0000-0000-000000000001"),
			Role:             string(n.Role),
			Addr:             n.Addr,
			HealthPath:       n.HealthPath,
			Healthy:          n.Healthy,
			ConsecutiveFails: n.FailStreak,
			PolicyVersion:    n.PolicyVer,
			Region:           "default",
		}
		if err := nodeDB.Upsert(rec); err != nil {
			slog.Warn("failed to upsert node to database", "node", n.ID, "err", err)
		}
	})

	// ── Policy signing keypair ────────────────────────────────────────────────
	// Ed25519 keypair persisted to ~/.tsm/policy-signing.{key,pub}.
	// All GET /config/policy responses carry X-TSM-Policy-Signature so that
	// dataplanes can verify authenticity before applying any policy update.
	policySigner, err := policy.NewSigner()
	if err != nil {
		slog.Warn("policy signer unavailable — unsigned policy will be distributed", "err", err)
	} else {
		slog.Info("policy signer ready", "pub_key_b64", policySigner.PubB64)
	}

	// ── Priority queue ────────────────────────────────────────────────────────
	goldLimit   := envInt64("TSM_QUEUE_GOLD_LIMIT",   0)   // 0 = unlimited
	silverLimit := envInt64("TSM_QUEUE_SILVER_LIMIT", 500)
	bronzeLimit := envInt64("TSM_QUEUE_BRONZE_LIMIT", 50)
	queueTracker := queue.NewTracker(goldLimit, silverLimit, bronzeLimit)

	slog.Info("priority queue configured",
		"gold_limit", goldLimit, "silver_limit", silverLimit, "bronze_limit", bronzeLimit)

	// ── Human-in-the-loop suggestion store ───────────────────────────────────
	suggestionStore := suggestion.NewStore(func(rule suggestion.RuleSpec) error {
		// Convert suggestion.RuleSpec → policy.Rule and merge into live policy.
		// Conditions are mapped from RuleSpec.Conditions (generic map) to
		// policy.Rule.Condition.  If no conditions are provided, default to
		// an always-match condition so the rule is immediately active.
		cond := rule.Conditions
		if len(cond) == 0 {
			cond = map[string]any{"always": true}
		}
		pr := policy.Rule{
			Name:      rule.Name,
			Action:    rule.Action,
			Priority:  rule.Priority,
			Enabled:   true,
			Condition: cond,
		}
		policyStore.PatchRule(pr)
		slog.Info("suggestion approved and merged into policy", "rule", rule.Name)
		return nil
	})

	// ── Background health poller ──────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	go registry.StartHealthPoller(ctx, pollInterval)

	// ── HTTP server ───────────────────────────────────────────────────────────
	handler := api.New(policyStore, registry, queueTracker, suggestionStore, policySigner)
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start in a goroutine so we can catch signals below
	go func() {
		slog.Info("control plane listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down control plane")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
	}
	slog.Info("control plane stopped")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[control-plane] invalid %s=%q: %v — using default %d\n", key, v, err, def)
		return def
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[control-plane] invalid %s=%q: %v — using default %s\n", key, v, err, def)
		return def
	}
	return d
}
