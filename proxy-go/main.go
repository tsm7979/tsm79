// TSM Go Proxy — High-performance AI traffic firewall
//
// Why Go?
//   - goroutine-per-request model handles 50k+ concurrent connections trivially
//   - compiled regex: pattern matching in <0.5ms per request
//   - zero-copy I/O with net/http
//   - HMAC-chained audit log: tamper-proof, append-only
//   - Prometheus metrics built in
//   - sub-5ms end-to-end PII detection on warm paths
//
// Architecture:
//   Client → Go Proxy (fast-path regex + circuit breaker + rate limit)
//          → Python Detector (deep ML scan, async)
//          → Upstream AI (OpenAI / Anthropic / Ollama)
//          → HMAC Audit Log (tamper-proof append-only file)

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

	"github.com/tsm7979/tsm79/proxy-go/audit"
	"github.com/tsm7979/tsm79/proxy-go/handler"
)

func main() {
	port        := envOr("TSM_GO_PORT",    "8090")
	detectorURL := envOr("TSM_DETECTOR_URL", "http://localhost:8001")
	auditPath   := envOr("TSM_AUDIT_LOG",  "audit.jsonl")
	auditSecret := envOr("TSM_AUDIT_SECRET", "change-me-in-production")
	if auditSecret == "change-me-in-production" {
		// Warn loudly — default secret compromises the tamper-proof audit chain.
		// Set TSM_AUDIT_SECRET to a random 32+ byte secret in production.
		fmt.Fprintln(os.Stderr, "[TSM] WARNING: TSM_AUDIT_SECRET is using the default value. Set a strong secret in production.")
	}

	// ── Structured logger ────────────────────────────────────────────────────
	logLevel := slog.LevelInfo
	if os.Getenv("TSM_LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	// ── Tamper-proof audit log ───────────────────────────────────────────────
	al, err := audit.New(auditPath, auditSecret)
	if err != nil {
		slog.Error("failed to open audit log", "path", auditPath, "err", err)
		os.Exit(1)
	}
	defer al.Close()

	// ── HTTP handler ─────────────────────────────────────────────────────────
	mux := handler.New(detectorURL, al)

	srv := &http.Server{
		Addr:         "0.0.0.0:" + port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("TSM Go Proxy starting",
			"addr", srv.Addr,
			"detector", detectorURL,
			"audit_log", auditPath,
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
	slog.Info("stopped")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
