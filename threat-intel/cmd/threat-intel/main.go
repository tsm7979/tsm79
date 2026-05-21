// TSM Threat Intelligence Service
//
// A real-time threat feed aggregator that populates Redis with:
//   - IP reputation data (AbuseIPDB, OTX, NVD)
//   - Known Exploited Vulnerabilities (CISA KEV, NVD)
//   - Tor exit nodes (Tor Project bulk list)
//   - VPN exit nodes (public CIDR lists)
//   - MITRE ATT&CK techniques and malware
//   - XDP kernel blocklist (IPs to drop at NIC driver level)
//
// The Rust dataplane reads the IP reputation and IOC stores via Redis.
// The eBPF loader reads tsm:xdp:blocklist to program the kernel BPF map.
//
// Usage:
//   threat-intel [flags]
//
// Environment:
//   TSM_REDIS_URL         redis://localhost:6379              (required)
//   TSM_LISTEN_ADDR       :9100                               (optional)
//   TSM_NVD_API_KEY       <key>                               (optional, higher rate limit)
//   TSM_ABUSEIPDB_KEY     <key>                               (required for AbuseIPDB feed)
//   TSM_OTX_API_KEY       <key>                               (required for OTX feed)
//   TSM_LOG_LEVEL         info | debug | warn                  (optional)

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/tsm-ai/threat-intel/internal/feeds"
	"github.com/tsm-ai/threat-intel/internal/server"
	"github.com/tsm-ai/threat-intel/internal/store"
)

func main() {
	// ── Flags ─────────────────────────────────────────────────────────────────
	redisURL  := flag.String("redis",  envOrDefault("TSM_REDIS_URL", "localhost:6379"), "Redis address (host:port or redis://...)")
	listenAddr := flag.String("listen", envOrDefault("TSM_LISTEN_ADDR", ":9100"), "HTTP listen address")
	logLevel   := flag.String("log",    envOrDefault("TSM_LOG_LEVEL", "info"), "Log level: debug|info|warn|error")
	pollOnce   := flag.Bool("once", false, "Poll all feeds once and exit (useful for testing)")
	flag.Parse()

	// ── Logger ────────────────────────────────────────────────────────────────
	log := buildLogger(*logLevel)
	defer log.Sync() //nolint:errcheck

	log.Info("TSM Threat Intelligence Service starting",
		zap.String("redis", *redisURL),
		zap.String("listen", *listenAddr),
	)

	// ── Redis connection ───────────────────────────────────────────────────────
	redisAddr := stripRedisScheme(*redisURL)
	db, err := store.New(redisAddr, os.Getenv("TSM_REDIS_PASSWORD"), 0, log)
	if err != nil {
		log.Fatal("failed to connect to Redis", zap.Error(err))
	}
	defer db.Close()

	// ── Feeds ─────────────────────────────────────────────────────────────────
	feedCfg := feeds.Config{
		NVDAPIKey:    os.Getenv("TSM_NVD_API_KEY"),
		AbuseIPDBKey: os.Getenv("TSM_ABUSEIPDB_KEY"),
		OTXAPIKey:    os.Getenv("TSM_OTX_API_KEY"),
	}
	allFeeds := feeds.AllFeeds(feedCfg, log)

	// ── Context / signals ──────────────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Info("signal received, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	// ── One-shot mode ──────────────────────────────────────────────────────────
	if *pollOnce {
		log.Info("--once mode: polling all feeds once")
		var wg sync.WaitGroup
		for _, feed := range allFeeds {
			wg.Add(1)
			go func(f feeds.Feed) {
				defer wg.Done()
				pollFeed(ctx, f, db, log)
			}(feed)
		}
		wg.Wait()
		log.Info("one-shot poll complete")
		return
	}

	// ── HTTP server ────────────────────────────────────────────────────────────
	srv := server.New(db, log)
	go func() {
		if err := srv.Start(ctx, *listenAddr); err != nil {
			log.Error("HTTP server error", zap.Error(err))
			cancel()
		}
	}()

	// ── Feed schedulers ────────────────────────────────────────────────────────
	// Do an initial poll of all feeds immediately on startup, then schedule
	// each feed on its own interval.  Feeds run concurrently but each feed
	// runs sequentially with itself (no concurrent poll of the same feed).
	var wg sync.WaitGroup
	for _, feed := range allFeeds {
		wg.Add(1)
		go func(f feeds.Feed) {
			defer wg.Done()
			runFeedLoop(ctx, f, db, log)
		}(feed)
	}

	log.Info("all feed schedulers started", zap.Int("feeds", len(allFeeds)))
	wg.Wait()
	log.Info("threat-intel service stopped")
}

// runFeedLoop polls a single feed immediately, then on its interval, until ctx is cancelled.
func runFeedLoop(ctx context.Context, f feeds.Feed, db *store.ThreatDB, log *zap.Logger) {
	log.Info("feed starting", zap.String("feed", f.Name()), zap.Duration("interval", f.Interval()))

	// Initial poll
	pollFeed(ctx, f, db, log)

	ticker := time.NewTicker(f.Interval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("feed stopping", zap.String("feed", f.Name()))
			return
		case <-ticker.C:
			pollFeed(ctx, f, db, log)
		}
	}
}

// pollFeed wraps a single feed poll with timing, error handling, and stat recording.
func pollFeed(ctx context.Context, f feeds.Feed, db *store.ThreatDB, log *zap.Logger) {
	start := time.Now()
	count, err := f.Poll(ctx, db)
	elapsed := time.Since(start)

	stats := store.FeedStats{
		FeedName:    f.Name(),
		LastPollAt:  time.Now(),
		RecordCount: count,
	}

	if err != nil {
		log.Error("feed poll failed",
			zap.String("feed", f.Name()),
			zap.Duration("elapsed", elapsed),
			zap.Error(err),
		)
		stats.ErrorCount = 1
		stats.LastErrorMsg = err.Error()
	} else {
		log.Info("feed poll OK",
			zap.String("feed", f.Name()),
			zap.Int("records", count),
			zap.Duration("elapsed", elapsed),
		)
	}

	pollCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	db.RecordFeedPoll(pollCtx, stats) //nolint:errcheck
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// stripRedisScheme converts redis://host:port or rediss://host:port to host:port.
func stripRedisScheme(u string) string {
	for _, prefix := range []string{"rediss://", "redis://"} {
		if after, ok := strings.CutPrefix(u, prefix); ok {
			// Strip any auth portion (user:pass@host:port → host:port)
			if idx := strings.LastIndex(after, "@"); idx != -1 {
				return after[idx+1:]
			}
			return after
		}
	}
	return u
}

func buildLogger(level string) *zap.Logger {
	var lvl zapcore.Level
	switch level {
	case "debug":
		lvl = zapcore.DebugLevel
	case "warn":
		lvl = zapcore.WarnLevel
	case "error":
		lvl = zapcore.ErrorLevel
	default:
		lvl = zapcore.InfoLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	log, err := cfg.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build logger: %v\n", err)
		os.Exit(1)
	}
	return log
}
