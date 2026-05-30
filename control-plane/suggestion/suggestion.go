// Package suggestion implements the TSM human-in-the-loop (HITL) policy
// suggestion workflow.
//
// Design:
//
//   Automated systems (anomaly detectors, threat intel feeds, LLM-assisted
//   analysis) can POST a Suggestion — a proposed new or updated policy rule
//   with a confidence score and human-readable rationale.  The suggestion
//   enters PENDING state and is surfaced to a human reviewer via
//   GET /config/policy/suggestions.
//
//   A human operator (CISO / security engineer) reviews the suggestion and
//   either approves it (merging the rule into the live policy via the
//   policy.Store) or rejects it (recording the decision with a reason).
//
//   IMPORTANT: No suggestion is ever automatically promoted to the live policy.
//   Every approval requires an explicit human action.  This satisfies
//   AI-assisted-but-human-controlled security policy requirements from NIST
//   800-53 (SI-7) and enterprise governance frameworks.
//
// Endpoints (wired in api/handler.go):
//
//   POST   /config/policy/suggestions           — create suggestion
//   GET    /config/policy/suggestions           — list (filter: ?status=pending)
//   GET    /config/policy/suggestions/{id}      — get one
//   PUT    /config/policy/suggestions/{id}/approve — approve and merge
//   PUT    /config/policy/suggestions/{id}/reject  — reject with reason

package suggestion

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ── Status constants ──────────────────────────────────────────────────────────

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
)

// ── Prometheus metrics ────────────────────────────────────────────────────────

var (
	suggestionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tsm_suggestions_total",
		Help: "Total policy suggestions by final status.",
	}, []string{"status"})

	suggestionsPending = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "tsm_suggestions_pending",
		Help: "Number of policy suggestions currently awaiting human review.",
	})
)

// ── Types ─────────────────────────────────────────────────────────────────────

// RuleSpec is the proposed rule content inside a suggestion.
// Mirrors policy.Rule but kept separate so this package has no import cycle.
type RuleSpec struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Action      string            `json:"action"`    // "block" | "redact" | "allow" | "route_local"
	Priority    int               `json:"priority"`
	Conditions  map[string]any    `json:"conditions"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Suggestion is a proposed policy rule awaiting human review.
type Suggestion struct {
	ID          string     `json:"id"`
	Rule        RuleSpec   `json:"rule"`
	Reason      string     `json:"reason"`       // why this rule is suggested
	Source      string     `json:"source"`       // e.g. "anomaly-detector", "threat-intel", "manual"
	Confidence  float64    `json:"confidence"`   // 0.0–1.0
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ReviewedBy  string     `json:"reviewed_by,omitempty"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	RejectReason string    `json:"reject_reason,omitempty"`
}

// ApproveRequest is the body for the approve endpoint.
type ApproveRequest struct {
	ReviewedBy string `json:"reviewed_by"` // username / email of approver
}

// RejectRequest is the body for the reject endpoint.
type RejectRequest struct {
	ReviewedBy   string `json:"reviewed_by"`
	RejectReason string `json:"reject_reason"`
}

// ── Errors ────────────────────────────────────────────────────────────────────

var (
	ErrNotFound    = fmt.Errorf("suggestion not found")
	ErrNotPending  = fmt.Errorf("suggestion is no longer pending")
)

// ── Store ─────────────────────────────────────────────────────────────────────

// Store holds all suggestions in memory.  For production deployments this
// should be backed by a persistent store (Postgres, etcd); for now the
// in-memory implementation is sufficient for single-instance control planes.
type Store struct {
	mu          sync.RWMutex
	suggestions map[string]*Suggestion
	// onApprove is called when a suggestion is approved.
	// The caller (handler.go) uses this to merge the rule into the policy store.
	onApprove func(rule RuleSpec) error
}

// NewStore creates a suggestion store.  onApprove is called synchronously when
// a suggestion is approved; it should merge the rule into the live policy.
func NewStore(onApprove func(rule RuleSpec) error) *Store {
	return &Store{
		suggestions: make(map[string]*Suggestion),
		onApprove:   onApprove,
	}
}

// Create records a new suggestion and returns it in PENDING state.
func (s *Store) Create(rule RuleSpec, reason, source string, confidence float64) (*Suggestion, error) {
	if rule.Name == "" {
		return nil, fmt.Errorf("rule.name is required")
	}
	if confidence < 0 || confidence > 1 {
		return nil, fmt.Errorf("confidence must be in [0.0, 1.0]")
	}

	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("id generation: %w", err)
	}

	sug := &Suggestion{
		ID:         id,
		Rule:       rule,
		Reason:     reason,
		Source:     source,
		Confidence: confidence,
		Status:     StatusPending,
		CreatedAt:  time.Now().UTC(),
	}

	s.mu.Lock()
	s.suggestions[id] = sug
	s.mu.Unlock()

	suggestionsPending.Inc()
	return sug, nil
}

// Get returns one suggestion by ID.
func (s *Store) Get(id string) (*Suggestion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sug, ok := s.suggestions[id]
	if !ok {
		return nil, ErrNotFound
	}
	// Return a copy to avoid data races on the caller side
	copy := *sug
	return &copy, nil
}

// List returns all suggestions, optionally filtered by status.
// status="" returns all; status="pending" returns only pending ones.
func (s *Store) List(status string) []*Suggestion {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Suggestion, 0, len(s.suggestions))
	for _, sug := range s.suggestions {
		if status == "" || sug.Status == status {
			copy := *sug
			out = append(out, &copy)
		}
	}
	return out
}

// Approve approves a PENDING suggestion, merging its rule into the live policy.
func (s *Store) Approve(id, reviewedBy string) (*Suggestion, error) {
	s.mu.Lock()
	sug, ok := s.suggestions[id]
	if !ok {
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	if sug.Status != StatusPending {
		s.mu.Unlock()
		return nil, ErrNotPending
	}

	// Call the merge hook before committing the status change
	rule := sug.Rule
	s.mu.Unlock()

	if err := s.onApprove(rule); err != nil {
		return nil, fmt.Errorf("policy merge failed: %w", err)
	}

	now := time.Now().UTC()
	s.mu.Lock()
	sug.Status     = StatusApproved
	sug.ReviewedBy = reviewedBy
	sug.ReviewedAt = &now
	copy := *sug
	s.mu.Unlock()

	suggestionsPending.Dec()
	suggestionsTotal.WithLabelValues(StatusApproved).Inc()
	return &copy, nil
}

// Reject marks a PENDING suggestion as rejected.
func (s *Store) Reject(id, reviewedBy, reason string) (*Suggestion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sug, ok := s.suggestions[id]
	if !ok {
		return nil, ErrNotFound
	}
	if sug.Status != StatusPending {
		return nil, ErrNotPending
	}
	now := time.Now().UTC()
	sug.Status       = StatusRejected
	sug.ReviewedBy   = reviewedBy
	sug.ReviewedAt   = &now
	sug.RejectReason = reason
	copy := *sug
	suggestionsPending.Dec()
	suggestionsTotal.WithLabelValues(StatusRejected).Inc()
	return &copy, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sug-" + hex.EncodeToString(b), nil
}
