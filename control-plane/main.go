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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tsm7979/tsm/control-plane/api"
	"github.com/tsm7979/tsm/control-plane/cluster"
	"github.com/tsm7979/tsm/control-plane/policy"
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

	// ── Core subsystems ───────────────────────────────────────────────────────
	policyStore := policy.NewStore()
	registry    := cluster.NewRegistry()

	// ── Background health poller ──────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	go registry.StartHealthPoller(ctx, pollInterval)

	// ── HTTP server ───────────────────────────────────────────────────────────
	handler := api.New(policyStore, registry)
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
