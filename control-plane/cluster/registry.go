// Package cluster tracks registered dataplane and proxy nodes.
//
// Each node self-registers by POSTing to /nodes/register with its address and
// role.  The control plane health-checks each node every 10 seconds and marks
// it unhealthy if it misses 3 consecutive checks.
package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Role identifies the function of a registered node.
type Role string

const (
	RoleDataplane Role = "dataplane"
	RoleProxy     Role = "proxy"
	RoleDetector  Role = "detector"
)

// Node is a registered cluster member.
type Node struct {
	ID          string    `json:"id"`
	Role        Role      `json:"role"`
	Addr        string    `json:"addr"`        // "host:port"
	HealthPath  string    `json:"health_path"` // e.g. "/api/health"
	Healthy     bool      `json:"healthy"`
	LastSeen    time.Time `json:"last_seen"`
	FailStreak  int       `json:"fail_streak"`
	PolicyVer   int64     `json:"policy_version"` // last applied policy version
}

// Registry is a thread-safe set of cluster nodes.
type Registry struct {
	mu           sync.RWMutex
	nodes        map[string]*Node
	onNodeUpdate func(*Node) // optional persistence hook
}

func NewRegistry() *Registry {
	return &Registry{nodes: make(map[string]*Node)}
}

// OnNodeUpdate registers a hook called after every Register/Deregister/health change.
// The hook receives a copy of the node and is called with the mutex released.
func (r *Registry) OnNodeUpdate(fn func(*Node)) {
	r.mu.Lock()
	r.onNodeUpdate = fn
	r.mu.Unlock()
}

// Register adds or refreshes a node.
func (r *Registry) Register(id string, role Role, addr, healthPath string) *Node {
	r.mu.Lock()
	n, ok := r.nodes[id]
	if !ok {
		n = &Node{ID: id, Role: role, Addr: addr, HealthPath: healthPath, Healthy: true}
		r.nodes[id] = n
	}
	n.LastSeen = time.Now().UTC()
	n.Healthy = true
	n.FailStreak = 0
	cp := *n
	hook := r.onNodeUpdate
	r.mu.Unlock()
	if hook != nil {
		hook(&cp)
	}
	return n
}

// Deregister removes a node.
func (r *Registry) Deregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.nodes, id)
}

// All returns a snapshot of all registered nodes.
func (r *Registry) All() []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		cp := *n
		out = append(out, &cp)
	}
	return out
}

// Healthy returns only healthy nodes of the given role.
func (r *Registry) Healthy(role Role) []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Node
	for _, n := range r.nodes {
		if n.Role == role && n.Healthy {
			cp := *n
			out = append(out, &cp)
		}
	}
	return out
}

// UpdatePolicyVersion records which policy version a node has applied.
func (r *Registry) UpdatePolicyVersion(id string, ver int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n, ok := r.nodes[id]; ok {
		n.PolicyVer = ver
	}
}

// markHealth sets the healthy flag and resets or increments the fail streak.
func (r *Registry) markHealth(id string, healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[id]
	if !ok {
		return
	}
	if healthy {
		n.Healthy = true
		n.FailStreak = 0
		n.LastSeen = time.Now().UTC()
	} else {
		n.FailStreak++
		if n.FailStreak >= 3 {
			n.Healthy = false
		}
	}
}

// ── Health poller ─────────────────────────────────────────────────────────────

// StartHealthPoller polls all registered nodes every `interval` and marks
// them healthy or unhealthy.  Runs until ctx is cancelled.
func (r *Registry) StartHealthPoller(ctx context.Context, interval time.Duration) {
	client := &http.Client{Timeout: 3 * time.Second}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.pollAll(client)
		}
	}
}

func (r *Registry) pollAll(client *http.Client) {
	r.mu.RLock()
	ids := make([]string, 0, len(r.nodes))
	addrs := make(map[string]string)
	paths := make(map[string]string)
	for id, n := range r.nodes {
		ids = append(ids, id)
		addrs[id] = n.Addr
		paths[id] = n.HealthPath
	}
	r.mu.RUnlock()

	for _, id := range ids {
		go func(id, addr, path string) {
			url := fmt.Sprintf("http://%s%s", addr, path)
			resp, err := client.Get(url)
			ok := err == nil && resp.StatusCode < 300
			if resp != nil {
				resp.Body.Close()
			}
			if !ok {
				slog.Warn("node health check failed", "id", id, "url", url, "err", err)
			}
			r.markHealth(id, ok)
		}(id, addrs[id], paths[id])
	}
}
