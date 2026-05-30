// Package server provides the HTTP API for the threat intelligence service.
//
// Endpoints consumed by the Rust dataplane and eBPF loader:
//
//   GET  /intel/ip/<ip>           → IPRecord JSON (404 if unknown)
//   GET  /intel/ioc/<indicator>   → IOCRecord JSON (404 if unknown)
//   GET  /intel/blocklist         → []BlocklistEntry JSON
//   GET  /intel/blocklist/size    → {"size": N}
//   POST /intel/block             → add IP to XDP blocklist
//   POST /intel/unblock           → remove IP from XDP blocklist
//   GET  /intel/tor/<ip>          → {"is_tor": true/false}
//   GET  /feeds/stats             → []FeedStats JSON
//   GET  /health                  → {"status":"ok","feeds":[...]}
//   GET  /metrics                 → Prometheus text exposition

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/tsm-ai/threat-intel/internal/store"
)

// Server is the threat intelligence HTTP API server.
type Server struct {
	db  *store.ThreatDB
	log *zap.Logger
	mux *http.ServeMux
	srv *http.Server
}

// New creates a new Server.
func New(db *store.ThreatDB, log *zap.Logger) *Server {
	s := &Server{
		db:  db,
		log: log,
		mux: http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/intel/ip/", s.handleGetIP)
	s.mux.HandleFunc("/intel/ioc/", s.handleGetIOC)
	s.mux.HandleFunc("/intel/blocklist", s.handleBlocklist)
	s.mux.HandleFunc("/intel/blocklist/size", s.handleBlocklistSize)
	s.mux.HandleFunc("/intel/block", s.handleBlock)
	s.mux.HandleFunc("/intel/unblock", s.handleUnblock)
	s.mux.HandleFunc("/intel/tor/", s.handleIsTor)
	s.mux.HandleFunc("/feeds/stats", s.handleFeedStats)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
}

// Start listens on addr and serves until the context is cancelled.
func (s *Server) Start(ctx context.Context, addr string) error {
	s.srv = &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.srv.Shutdown(shutCtx) //nolint:errcheck
	}()

	s.log.Info("threat-intel HTTP server starting", zap.String("addr", addr))
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

// ── Handler helpers ───────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func pathSuffix(r *http.Request, prefix string) string {
	return strings.TrimPrefix(r.URL.Path, prefix)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// GET /intel/ip/<ip>
func (s *Server) handleGetIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	ip := pathSuffix(r, "/intel/ip/")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip required")
		return
	}

	rec, err := s.db.GetIP(r.Context(), ip)
	if err != nil {
		s.log.Error("GetIP error", zap.String("ip", ip), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if rec == nil {
		writeError(w, http.StatusNotFound, "unknown")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// GET /intel/ioc/<indicator>
func (s *Server) handleGetIOC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	indicator := pathSuffix(r, "/intel/ioc/")
	if indicator == "" {
		writeError(w, http.StatusBadRequest, "indicator required")
		return
	}

	ioc, err := s.db.GetIOC(r.Context(), indicator)
	if err != nil {
		s.log.Error("GetIOC error", zap.String("ind", indicator), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if ioc == nil {
		writeError(w, http.StatusNotFound, "unknown")
		return
	}
	writeJSON(w, http.StatusOK, ioc)
}

// GET /intel/blocklist
func (s *Server) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/intel/blocklist/size" {
		s.handleBlocklistSize(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	entries, err := s.db.GetBlocklist(r.Context())
	if err != nil {
		s.log.Error("GetBlocklist error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// GET /intel/blocklist/size
func (s *Server) handleBlocklistSize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	n, err := s.db.BlocklistSize(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"size": n})
}

// POST /intel/block  body: {"ip":"1.2.3.4","reason":"manual","ttl_hours":24}
func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		TTLHours int    `json:"ttl_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.TTLHours <= 0 {
		req.TTLHours = 24
	}
	entry := store.BlocklistEntry{
		IP:        req.IP,
		Reason:    req.Reason,
		AddedAt:   time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(req.TTLHours) * time.Hour),
	}
	if err := s.db.BlockIP(r.Context(), entry); err != nil {
		s.log.Error("BlockIP error", zap.String("ip", req.IP), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "block failed")
		return
	}
	s.log.Info("IP blocked via API", zap.String("ip", req.IP), zap.String("reason", req.Reason))
	writeJSON(w, http.StatusOK, map[string]string{"status": "blocked", "ip": req.IP})
}

// POST /intel/unblock  body: {"ip":"1.2.3.4"}
func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.db.UnblockIP(r.Context(), req.IP); err != nil {
		writeError(w, http.StatusInternalServerError, "unblock failed")
		return
	}
	s.log.Info("IP unblocked via API", zap.String("ip", req.IP))
	writeJSON(w, http.StatusOK, map[string]string{"status": "unblocked", "ip": req.IP})
}

// GET /intel/tor/<ip>
func (s *Server) handleIsTor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	ip := pathSuffix(r, "/intel/tor/")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip required")
		return
	}
	isTor, err := s.db.IsTor(r.Context(), ip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"is_tor": isTor})
}

// GET /feeds/stats
func (s *Server) handleFeedStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	stats, err := s.db.GetFeedStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// GET /health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	redisOK := s.db.Ping(ctx) == nil

	torSize, _ := s.db.TorSetSize(ctx)
	blSize, _ := s.db.BlocklistSize(ctx)

	status := "ok"
	httpStatus := http.StatusOK
	if !redisOK {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	writeJSON(w, httpStatus, map[string]interface{}{
		"status":          status,
		"redis":           redisOK,
		"tor_nodes":       torSize,
		"blocked_ips":     blSize,
		"timestamp":       time.Now().UTC(),
	})
}

// GET /metrics — minimal Prometheus exposition
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	torSize, _ := s.db.TorSetSize(ctx)
	blSize, _ := s.db.BlocklistSize(ctx)
	stats, _ := s.db.GetFeedStats(ctx)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP tsm_intel_tor_nodes Known Tor exit nodes\n")
	fmt.Fprintf(w, "# TYPE tsm_intel_tor_nodes gauge\n")
	fmt.Fprintf(w, "tsm_intel_tor_nodes %d\n", torSize)
	fmt.Fprintf(w, "# HELP tsm_intel_blocked_ips IPs in XDP blocklist\n")
	fmt.Fprintf(w, "# TYPE tsm_intel_blocked_ips gauge\n")
	fmt.Fprintf(w, "tsm_intel_blocked_ips %d\n", blSize)
	for _, s := range stats {
		fmt.Fprintf(w, "# HELP tsm_intel_feed_last_poll_timestamp_seconds Last poll for feed %s\n", s.FeedName)
		fmt.Fprintf(w, "tsm_intel_feed_last_poll_timestamp_seconds{feed=%q} %d\n",
			s.FeedName, s.LastPollAt.Unix())
	}
}
