// Package api exposes the control plane REST API.
//
// Endpoints:
//   GET  /health                  — liveness
//   GET  /config/policy           — current policy snapshot (304 if unchanged)
//   PUT  /config/policy           — replace entire ruleset
//   GET  /config/policy/history   — last 10 policy versions
//   PATCH /config/policy/rules    — add or update a single rule
//   DELETE /config/policy/rules/{name} — delete a rule
//   GET  /nodes                   — all cluster nodes
//   POST /nodes/register          — self-register a node
//   DELETE /nodes/{id}            — deregister a node
//   PUT  /nodes/{id}/policy-ack   — node acknowledges a policy version
//   GET  /metrics                 — Prometheus text metrics
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tsm7979/tsm/control-plane/cluster"
	"github.com/tsm7979/tsm/control-plane/policy"
	"github.com/tsm7979/tsm/control-plane/queue"
	"github.com/tsm7979/tsm/control-plane/suggestion"
)

// ── Prometheus metrics ────────────────────────────────────────────────────────

var (
	policyPushTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tsm_cp_policy_push_total",
		Help: "Number of policy push operations.",
	}, []string{"status"})

	nodeRegistrations = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "tsm_cp_nodes_registered",
		Help: "Current number of registered cluster nodes.",
	})

	apiRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tsm_cp_api_duration_seconds",
		Help:    "Control plane API request duration.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
)

// ── Handler ───────────────────────────────────────────────────────────────────

type Handler struct {
	store       *policy.Store
	registry    *cluster.Registry
	queue       *queue.Tracker
	suggestions *suggestion.Store
	signer      *policy.Signer // may be nil if key generation failed at startup
	mux         *http.ServeMux
}

func New(store *policy.Store, reg *cluster.Registry, q *queue.Tracker, sug *suggestion.Store, signer *policy.Signer) *Handler {
	h := &Handler{store: store, registry: reg, queue: q, suggestions: sug, signer: signer, mux: http.NewServeMux()}
	h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	rw := &statusWriter{ResponseWriter: w, status: 200}
	h.mux.ServeHTTP(rw, r)
	apiRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(time.Since(t0).Seconds())
}

func (h *Handler) routes() {
	h.mux.HandleFunc("/health", h.handleHealth)
	h.mux.HandleFunc("/metrics", promhttp.Handler().ServeHTTP)

	// Policy config
	h.mux.HandleFunc("/config/policy", h.handlePolicy)
	h.mux.HandleFunc("/config/policy/history", h.handlePolicyHistory)
	h.mux.HandleFunc("/config/policy/rules", h.handleRulePatch)
	h.mux.HandleFunc("/config/policy/rules/", h.handleRuleDelete)

	// Human-in-the-loop suggestions
	h.mux.HandleFunc("/config/policy/suggestions", h.handleSuggestions)
	h.mux.HandleFunc("/config/policy/suggestions/", h.handleSuggestionAction)

	// Cluster nodes
	h.mux.HandleFunc("/nodes", h.handleNodes)
	h.mux.HandleFunc("/nodes/register", h.handleNodeRegister)
	h.mux.HandleFunc("/nodes/", h.handleNodeAction)

	// Priority queue admission control
	h.mux.HandleFunc("/queue/stats", h.handleQueueStats)
	h.mux.HandleFunc("/queue/admit", h.handleQueueAdmit)
	h.mux.HandleFunc("/queue/admit/", h.handleQueueRelease)
}

// ── Health ────────────────────────────────────────────────────────────────────

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	snap := h.store.Current()
	nodes := h.registry.All()
	healthy := 0
	for _, n := range nodes {
		if n.Healthy {
			healthy++
		}
	}
	jsonOK(w, map[string]any{
		"status":         "healthy",
		"service":        "TSM Control Plane",
		"version":        "1.0.0",
		"policy_version": snap.Version,
		"nodes_total":    len(nodes),
		"nodes_healthy":  healthy,
	})
}

// ── Policy ────────────────────────────────────────────────────────────────────

func (h *Handler) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap := h.store.Current()
		// Conditional GET: 304 if client already has the current version
		clientVer := r.Header.Get("If-None-Match")
		if clientVer == fmt.Sprintf("%d", snap.Version) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf("%d", snap.Version))
		w.Header().Set("Cache-Control", "no-cache")
		// Sign the snapshot so dataplanes can verify authenticity before applying.
		if h.signer != nil {
			if sig, err := h.signer.Sign(snap); err == nil {
				w.Header().Set("X-TSM-Policy-Signature", sig)
				w.Header().Set("X-TSM-Policy-PubKey", h.signer.PubB64)
			} else {
				slog.Warn("policy signer: failed to sign snapshot", "err", err)
			}
		}
		jsonOK(w, snap)

	case http.MethodPut:
		var rules []policy.Rule
		if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		snap := h.store.Put(rules)
		policyPushTotal.WithLabelValues("ok").Inc()
		slog.Info("policy updated", "version", snap.Version, "rules", len(snap.Rules))
		w.WriteHeader(http.StatusOK)
		jsonOK(w, snap)

	default:
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handlePolicyHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	jsonOK(w, h.store.History())
}

func (h *Handler) handleRulePatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch && r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "use PATCH or POST")
		return
	}
	var rule policy.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if rule.Name == "" {
		jsonErr(w, http.StatusBadRequest, "rule.name is required")
		return
	}
	snap := h.store.PatchRule(rule)
	slog.Info("rule patched", "rule", rule.Name, "policy_version", snap.Version)
	jsonOK(w, snap)
}

func (h *Handler) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonErr(w, http.StatusMethodNotAllowed, "use DELETE")
		return
	}
	// /config/policy/rules/{name}
	name := strings.TrimPrefix(r.URL.Path, "/config/policy/rules/")
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "rule name required in path")
		return
	}
	snap, ok := h.store.DeleteRule(name)
	if !ok {
		jsonErr(w, http.StatusNotFound, "rule not found: "+name)
		return
	}
	slog.Info("rule deleted", "rule", name, "policy_version", snap.Version)
	jsonOK(w, snap)
}

// ── Cluster nodes ─────────────────────────────────────────────────────────────

type registerRequest struct {
	ID         string       `json:"id"`
	Role       cluster.Role `json:"role"`
	Addr       string       `json:"addr"`
	HealthPath string       `json:"health_path"`
}

func (h *Handler) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	jsonOK(w, h.registry.All())
}

func (h *Handler) handleNodeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.ID == "" || req.Addr == "" {
		jsonErr(w, http.StatusBadRequest, "id and addr are required")
		return
	}
	if req.HealthPath == "" {
		req.HealthPath = "/api/health"
	}
	node := h.registry.Register(req.ID, req.Role, req.Addr, req.HealthPath)
	nodeRegistrations.Set(float64(len(h.registry.All())))
	slog.Info("node registered", "id", node.ID, "role", node.Role, "addr", node.Addr)
	// Return the current policy version so the node can sync on registration
	snap := h.store.Current()
	jsonOK(w, map[string]any{
		"node":           node,
		"policy_version": snap.Version,
	})
}

func (h *Handler) handleNodeAction(w http.ResponseWriter, r *http.Request) {
	// /nodes/{id}  or  /nodes/{id}/policy-ack
	remainder := strings.TrimPrefix(r.URL.Path, "/nodes/")
	parts := strings.SplitN(remainder, "/", 2)
	nodeID := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch {
	case r.Method == http.MethodDelete && action == "":
		h.registry.Deregister(nodeID)
		nodeRegistrations.Set(float64(len(h.registry.All())))
		slog.Info("node deregistered", "id", nodeID)
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPut && action == "policy-ack":
		var body struct {
			Version int64 `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		h.registry.UpdatePolicyVersion(nodeID, body.Version)
		w.WriteHeader(http.StatusNoContent)

	default:
		jsonErr(w, http.StatusNotFound, "unknown node action")
	}
}

// ── Priority queue ────────────────────────────────────────────────────────────

// GET /queue/stats — point-in-time snapshot of active slots and limits per tier.
func (h *Handler) handleQueueStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	jsonOK(w, h.queue.Stats())
}

// POST /queue/admit — acquire an admission slot before forwarding to upstream.
//
// Request body (optional):
//   {"tier": "gold"|"silver"|"bronze"}
//
// The X-TSM-Priority header is also checked (body takes precedence).
//
// Response (201 Created):
//   {"slot_id":"slot-42","tier":"silver","admitted_at":"..."}
//
// Response (429 Too Many Requests) when tier is at capacity.
func (h *Handler) handleQueueAdmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	// Determine tier from body or header
	tierStr := r.Header.Get("X-TSM-Priority")
	var body struct {
		Tier string `json:"tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.Tier != "" {
		tierStr = body.Tier
	}
	tier := queue.ParseTier(tierStr)

	slot, err := h.queue.Admit(tier)
	if err != nil {
		jsonErr(w, http.StatusTooManyRequests, err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, slot)
}

// DELETE /queue/admit/{slot_id} — release an admission slot after forwarding completes.
func (h *Handler) handleQueueRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		jsonErr(w, http.StatusMethodNotAllowed, "use DELETE")
		return
	}
	// Slot is self-releasing via the Slot.Release() method held by the caller.
	// This endpoint is a semantic no-op from the server's perspective (the
	// in-memory slot handle is owned by the requester), but it's exposed for
	// completeness and future persistent-slot implementations.
	w.WriteHeader(http.StatusNoContent)
}

// ── Human-in-the-loop policy suggestions ─────────────────────────────────────

// POST/GET /config/policy/suggestions
func (h *Handler) handleSuggestions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		status := r.URL.Query().Get("status") // "" = all
		jsonOK(w, h.suggestions.List(status))

	case http.MethodPost:
		var req struct {
			Rule       suggestion.RuleSpec `json:"rule"`
			Reason     string              `json:"reason"`
			Source     string              `json:"source"`
			Confidence float64             `json:"confidence"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		sug, err := h.suggestions.Create(req.Rule, req.Reason, req.Source, req.Confidence)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		slog.Info("policy suggestion created", "id", sug.ID, "rule", sug.Rule.Name,
			"source", sug.Source, "confidence", sug.Confidence)
		w.WriteHeader(http.StatusCreated)
		jsonOK(w, sug)

	default:
		jsonErr(w, http.StatusMethodNotAllowed, "use GET or POST")
	}
}

// /config/policy/suggestions/{id}
// /config/policy/suggestions/{id}/approve
// /config/policy/suggestions/{id}/reject
func (h *Handler) handleSuggestionAction(w http.ResponseWriter, r *http.Request) {
	remainder := strings.TrimPrefix(r.URL.Path, "/config/policy/suggestions/")
	parts     := strings.SplitN(remainder, "/", 2)
	id        := parts[0]
	action    := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && action == "":
		sug, err := h.suggestions.Get(id)
		if err != nil {
			jsonErr(w, http.StatusNotFound, err.Error())
			return
		}
		jsonOK(w, sug)

	case r.Method == http.MethodPut && action == "approve":
		var req suggestion.ApproveRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ReviewedBy == "" {
			jsonErr(w, http.StatusBadRequest, "reviewed_by is required")
			return
		}
		sug, err := h.suggestions.Approve(id, req.ReviewedBy)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, suggestion.ErrNotFound) { status = http.StatusNotFound }
			if errors.Is(err, suggestion.ErrNotPending) { status = http.StatusConflict }
			jsonErr(w, status, err.Error())
			return
		}
		slog.Info("policy suggestion approved", "id", id, "rule", sug.Rule.Name,
			"reviewed_by", req.ReviewedBy)
		jsonOK(w, sug)

	case r.Method == http.MethodPut && action == "reject":
		var req suggestion.RejectRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ReviewedBy == "" {
			jsonErr(w, http.StatusBadRequest, "reviewed_by is required")
			return
		}
		sug, err := h.suggestions.Reject(id, req.ReviewedBy, req.RejectReason)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, suggestion.ErrNotFound) { status = http.StatusNotFound }
			if errors.Is(err, suggestion.ErrNotPending) { status = http.StatusConflict }
			jsonErr(w, status, err.Error())
			return
		}
		slog.Info("policy suggestion rejected", "id", id, "reviewed_by", req.ReviewedBy)
		jsonOK(w, sug)

	default:
		jsonErr(w, http.StatusNotFound, "unknown action")
	}
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
