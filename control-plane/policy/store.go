// Package policy stores versioned policy sets and distributes them to dataplane nodes.
//
// Each Put() increments the version monotonically.  Nodes poll /config/policy
// with an If-None-Match: <version> header; the control plane responds 304 when
// nothing changed, or 200 with the new policy JSON.
package policy

import (
	"encoding/json"
	"sync"
	"time"
)

// Rule mirrors the structure expected by the Rust PolicyEngine and Python policy_engine.
type Rule struct {
	Name      string         `json:"name"`
	Condition map[string]any `json:"condition"`
	Action    string         `json:"action"` // allow | block | redact | route_local
	Priority  int            `json:"priority"`
	Enabled   bool           `json:"enabled"`
}

// Snapshot is an immutable point-in-time policy version.
type Snapshot struct {
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Rules     []Rule    `json:"rules"`
}

// Store is a thread-safe versioned policy store.
type Store struct {
	mu       sync.RWMutex
	current  *Snapshot
	history  []*Snapshot // last 10 snapshots
}

func NewStore() *Store {
	initial := &Snapshot{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Rules:     defaultRules(),
	}
	return &Store{
		current: initial,
		history: []*Snapshot{initial},
	}
}

// Current returns the active policy snapshot (safe for concurrent reads).
func (s *Store) Current() *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Put replaces the active ruleset with `rules` and increments the version.
func (s *Store) Put(rules []Rule) *Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := &Snapshot{
		Version:   s.current.Version + 1,
		UpdatedAt: time.Now().UTC(),
		Rules:     rules,
	}
	s.current = snap
	s.history = append(s.history, snap)
	if len(s.history) > 10 {
		s.history = s.history[len(s.history)-10:]
	}
	return snap
}

// PatchRule adds or replaces a single named rule without touching others.
func (s *Store) PatchRule(rule Rule) *Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	rules := make([]Rule, 0, len(s.current.Rules)+1)
	patched := false
	for _, r := range s.current.Rules {
		if r.Name == rule.Name {
			rules = append(rules, rule)
			patched = true
		} else {
			rules = append(rules, r)
		}
	}
	if !patched {
		rules = append(rules, rule)
	}
	snap := &Snapshot{
		Version:   s.current.Version + 1,
		UpdatedAt: time.Now().UTC(),
		Rules:     rules,
	}
	s.current = snap
	s.history = append(s.history, snap)
	if len(s.history) > 10 {
		s.history = s.history[len(s.history)-10:]
	}
	return snap
}

// DeleteRule removes a rule by name, incrementing the version.
func (s *Store) DeleteRule(name string) (*Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rules := make([]Rule, 0, len(s.current.Rules))
	deleted := false
	for _, r := range s.current.Rules {
		if r.Name == name {
			deleted = true
		} else {
			rules = append(rules, r)
		}
	}
	if !deleted {
		return s.current, false
	}
	snap := &Snapshot{
		Version:   s.current.Version + 1,
		UpdatedAt: time.Now().UTC(),
		Rules:     rules,
	}
	s.current = snap
	return snap, true
}

// History returns the last N snapshots (oldest first).
func (s *Store) History() []*Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Snapshot, len(s.history))
	copy(out, s.history)
	return out
}

// JSON serialises the current snapshot.
func (s *Store) JSON() ([]byte, error) {
	return json.Marshal(s.Current())
}

// ── Built-in rules (matches Rust PolicyEngine::load_builtin_rules) ────────────

func defaultRules() []Rule {
	return []Rule{
		{
			Name:     "block-critical-pii-p10",
			Action:   "block",
			Priority: 10,
			Enabled:  true,
			Condition: map[string]any{
				"pii_types":  []string{"SSN", "CREDIT_CARD", "BANK_ACCOUNT"},
				"risk_score": map[string]any{"gte": 80},
			},
		},
		{
			Name:     "block-critical-secrets-p20",
			Action:   "block",
			Priority: 20,
			Enabled:  true,
			Condition: map[string]any{
				"pii_types": []string{"OPENAI_KEY", "ANTHROPIC_KEY", "GITHUB_TOKEN",
					"AWS_KEY", "PRIVATE_KEY"},
			},
		},
		{
			Name:     "block-jailbreak-p30",
			Action:   "block",
			Priority: 30,
			Enabled:  true,
			Condition: map[string]any{
				"pii_types": []string{"JAILBREAK"},
			},
		},
		{
			Name:     "redact-pii-p40",
			Action:   "redact",
			Priority: 40,
			Enabled:  true,
			Condition: map[string]any{
				"pii_types":  []string{"EMAIL", "PHONE", "IP_ADDRESS"},
				"risk_score": map[string]any{"gte": 40},
			},
		},
		{
			Name:     "allow-low-risk-p100",
			Action:   "allow",
			Priority: 100,
			Enabled:  true,
			Condition: map[string]any{
				"risk_score": map[string]any{"lt": 40},
			},
		},
	}
}
