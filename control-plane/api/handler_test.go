package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tsm7979/tsm/control-plane/api"
	"github.com/tsm7979/tsm/control-plane/cluster"
	"github.com/tsm7979/tsm/control-plane/policy"
	"github.com/tsm7979/tsm/control-plane/queue"
	"github.com/tsm7979/tsm/control-plane/suggestion"
)

func setup() (*api.Handler, *policy.Store, *cluster.Registry) {
	store := policy.NewStore()
	reg   := cluster.NewRegistry()
	q     := queue.NewTracker(0, 500, 50)
	sug   := suggestion.NewStore(func(r suggestion.RuleSpec) error {
		cond := r.Conditions
		if len(cond) == 0 {
			cond = map[string]any{"always": true}
		}
		store.PatchRule(policy.Rule{Name: r.Name, Action: r.Action, Priority: r.Priority, Enabled: true, Condition: cond})
		return nil
	})
	h := api.New(store, reg, q, sug, nil) // nil signer: tests don't need signed responses
	return h, store, reg
}

func TestHealthEndpoint(t *testing.T) {
	h, _, _ := setup()
	req  := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec  := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %v", body["status"])
	}
}

func TestGetPolicyCurrentVersion(t *testing.T) {
	h, store, _ := setup()
	// Initial version is 1 (built-in rules)
	req := httptest.NewRequest(http.MethodGet, "/config/policy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var snap policy.Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if snap.Version != store.Current().Version {
		t.Errorf("version mismatch: got %d, want %d", snap.Version, store.Current().Version)
	}
}

func TestConditionalGet304(t *testing.T) {
	h, store, _ := setup()
	ver := store.Current().Version
	req := httptest.NewRequest(http.MethodGet, "/config/policy", nil)
	req.Header.Set("If-None-Match", fmt.Sprintf("%d", ver))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", rec.Code)
	}
}

func TestPutPolicyReplacesRules(t *testing.T) {
	h, store, _ := setup()
	oldVer := store.Current().Version

	rules := []policy.Rule{{
		Name:     "test-block",
		Action:   "block",
		Priority: 5,
		Enabled:  true,
		Condition: map[string]any{"risk_score": map[string]any{"gte": 90}},
	}}
	body, _ := json.Marshal(rules)
	req := httptest.NewRequest(http.MethodPut, "/config/policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if store.Current().Version <= oldVer {
		t.Errorf("version should have incremented")
	}
	if len(store.Current().Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(store.Current().Rules))
	}
}

func TestNodeRegisterAndList(t *testing.T) {
	h, _, _ := setup()

	// Register a node
	reg := map[string]any{
		"id":          "node-1",
		"role":        "dataplane",
		"addr":        "10.0.0.1:8080",
		"health_path": "/api/health",
	}
	body, _ := json.Marshal(reg)
	req := httptest.NewRequest(http.MethodPost, "/nodes/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// List nodes
	req2 := httptest.NewRequest(http.MethodGet, "/nodes", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	var nodes []*cluster.Node
	if err := json.Unmarshal(rec2.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("list nodes: invalid JSON: %v", err)
	}
	if len(nodes) != 1 || nodes[0].ID != "node-1" {
		t.Errorf("expected node-1, got %+v", nodes)
	}
}

func TestQueueStatsEndpoint(t *testing.T) {
	h, _, _ := setup()
	req := httptest.NewRequest(http.MethodGet, "/queue/stats", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var stats map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// All tiers should be at zero active slots initially
	if active, ok := stats["gold_active"].(float64); !ok || active != 0 {
		t.Errorf("expected gold_active=0, got %v", stats["gold_active"])
	}
}

func TestQueueAdmitAndRelease(t *testing.T) {
	h, _, _ := setup()

	// POST /queue/admit with tier=silver
	body, _ := json.Marshal(map[string]string{"tier": "silver"})
	req := httptest.NewRequest(http.MethodPost, "/queue/admit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("admit: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var slot map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &slot); err != nil {
		t.Fatalf("admit: invalid JSON: %v", err)
	}
	if slot["tier"] != "silver" {
		t.Errorf("expected tier=silver, got %v", slot["tier"])
	}
	if slot["slot_id"] == "" {
		t.Errorf("expected non-empty slot_id")
	}
}

func TestQueueAdmitBronzeRejectedWhenFull(t *testing.T) {
	// Create a tracker with bronze limit of 0 (instantly full)
	store := policy.NewStore()
	reg   := cluster.NewRegistry()
	q     := queue.NewTracker(0, 500, 0) // bronzeLimit=0 → always reject
	sug   := suggestion.NewStore(func(r suggestion.RuleSpec) error { return nil })
	h     := api.New(store, reg, q, sug, nil)

	body, _ := json.Marshal(map[string]string{"tier": "bronze"})
	req := httptest.NewRequest(http.MethodPost, "/queue/admit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSuggestionCreateAndApprove(t *testing.T) {
	h, _, _ := setup()

	// Create a suggestion
	sug := map[string]any{
		"rule": map[string]any{
			"name":     "test-block-jailbreak",
			"action":   "block",
			"priority": 5,
		},
		"reason":     "high jailbreak attempt rate detected from org-42",
		"source":     "anomaly-detector",
		"confidence": 0.92,
	}
	body, _ := json.Marshal(sug)
	req := httptest.NewRequest(http.MethodPost, "/config/policy/suggestions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create suggestion: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("create: invalid JSON: %v", err)
	}
	if created["status"] != "pending" {
		t.Errorf("expected status=pending, got %v", created["status"])
	}
	id := created["id"].(string)

	// List pending suggestions — should contain our new one
	req2 := httptest.NewRequest(http.MethodGet, "/config/policy/suggestions?status=pending", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	var list []map[string]any
	json.Unmarshal(rec2.Body.Bytes(), &list)
	if len(list) == 0 {
		t.Fatalf("expected at least 1 pending suggestion")
	}

	// Approve the suggestion
	approveBody, _ := json.Marshal(map[string]string{"reviewed_by": "alice@example.com"})
	req3 := httptest.NewRequest(http.MethodPut,
		"/config/policy/suggestions/"+id+"/approve", bytes.NewReader(approveBody))
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("approve: expected 200, got %d: %s", rec3.Code, rec3.Body.String())
	}
	var approved map[string]any
	json.Unmarshal(rec3.Body.Bytes(), &approved)
	if approved["status"] != "approved" {
		t.Errorf("expected status=approved, got %v", approved["status"])
	}

	// Approving again should return 409 Conflict
	req4 := httptest.NewRequest(http.MethodPut,
		"/config/policy/suggestions/"+id+"/approve", bytes.NewReader(approveBody))
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusConflict {
		t.Errorf("double-approve: expected 409, got %d", rec4.Code)
	}
}

func TestPolicyResponseIncludesSignatureWhenSignerPresent(t *testing.T) {
	store := policy.NewStore()
	reg   := cluster.NewRegistry()
	q     := queue.NewTracker(0, 500, 50)
	sug   := suggestion.NewStore(func(r suggestion.RuleSpec) error { return nil })

	signer, err := policy.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	h := api.New(store, reg, q, sug, signer)

	req := httptest.NewRequest(http.MethodGet, "/config/policy", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	sig := rec.Header().Get("X-TSM-Policy-Signature")
	if sig == "" {
		t.Error("X-TSM-Policy-Signature header missing when signer is wired in")
	}
	pubKey := rec.Header().Get("X-TSM-Policy-PubKey")
	if pubKey == "" {
		t.Error("X-TSM-Policy-PubKey header missing when signer is wired in")
	}
}

func TestPatchRule(t *testing.T) {
	h, store, _ := setup()
	oldVer := store.Current().Version

	rule := policy.Rule{
		Name:     "new-rule",
		Action:   "redact",
		Priority: 15,
		Enabled:  true,
		Condition: map[string]any{"always": true},
	}
	body, _ := json.Marshal(rule)
	req := httptest.NewRequest(http.MethodPatch, "/config/policy/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("patch rule: expected 200, got %d", rec.Code)
	}
	if store.Current().Version <= oldVer {
		t.Errorf("version should have incremented")
	}
	found := false
	for _, r := range store.Current().Rules {
		if r.Name == "new-rule" {
			found = true
		}
	}
	if !found {
		t.Errorf("rule 'new-rule' not found after patch")
	}
}

