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
	store    *policy.Store
	registry *cluster.Registry
	mux      *http.ServeMux
}

func New(store *policy.Store, reg *cluster.Registry) *Handler {
	h := &Handler{store: store, registry: reg, mux: http.NewServeMux()}
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
	h.mux.HandleFunc("/config/policy/rules/", h.handleRuleDelete) // DELETE /config/policy/rules/{name}

	// Cluster nodes
	h.mux.HandleFunc("/nodes", h.handleNodes)
	h.mux.HandleFunc("/nodes/register", h.handleNodeRegister)
	h.mux.HandleFunc("/nodes/", h.handleNodeAction) // /nodes/{id} and /nodes/{id}/policy-ack
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
