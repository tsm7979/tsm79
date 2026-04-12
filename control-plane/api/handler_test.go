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
)

func setup() (*api.Handler, *policy.Store, *cluster.Registry) {
	store := policy.NewStore()
	reg   := cluster.NewRegistry()
	h     := api.New(store, reg)
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

