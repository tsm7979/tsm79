// Package queue implements a GOLD/SILVER/BRONZE priority tracker for TSM
// request admission control.
//
// Design philosophy:
//
//   TSM operates on a thread-per-connection model in the Rust dataplane.  The
//   Go control plane cannot intercept individual requests in-flight, but it can
//   expose an admission-control API that the dataplane calls before forwarding
//   to an upstream AI model.  Dataplanes obtain a slot via POST /queue/admit,
//   forward the request, then release it via DELETE /queue/admit/{slot_id}.
//
// Tiers:
//
//   GOLD   — reserved for high-priority / SLA-guaranteed principals.
//            No concurrency limit by default (set via TSM_QUEUE_GOLD_LIMIT).
//   SILVER — standard tenants.  Capped at TSM_QUEUE_SILVER_LIMIT concurrent
//            forwards (default: 500).
//   BRONZE — background / batch / free-tier traffic.  Capped at
//            TSM_QUEUE_BRONZE_LIMIT (default: 50); rejected with 429 when full.
//
// A request carrying the header "X-TSM-Priority: gold" is admitted as GOLD,
// "X-TSM-Priority: bronze" as BRONZE.  Absent / unknown → SILVER.
//
// Prometheus gauges track active slots per tier; counters track lifetime
// admits and rejects.

package queue

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ── Tier enum ─────────────────────────────────────────────────────────────────

type Tier int

const (
	TierGold   Tier = 0
	TierSilver Tier = 1
	TierBronze Tier = 2
)

func (t Tier) String() string {
	switch t {
	case TierGold:
		return "gold"
	case TierSilver:
		return "silver"
	case TierBronze:
		return "bronze"
	default:
		return "unknown"
	}
}

// ParseTier maps a string value (from X-TSM-Priority header) to a Tier.
// Unknown strings default to SILVER.
func ParseTier(s string) Tier {
	switch s {
	case "gold":
		return TierGold
	case "bronze":
		return TierBronze
	default:
		return TierSilver
	}
}

// ── Slot ──────────────────────────────────────────────────────────────────────

// Slot is an admitted request handle.  The holder must call Release() when the
// upstream forward completes.
type Slot struct {
	ID        string    `json:"slot_id"`
	Tier      string    `json:"tier"`
	AdmitTime time.Time `json:"admitted_at"`
	tracker   *Tracker
	tierEnum  Tier
	released  atomic.Bool
}

// Release returns the slot to the tracker.  Safe to call multiple times (idempotent).
func (s *Slot) Release() {
	if s.released.CompareAndSwap(false, true) {
		s.tracker.release(s.tierEnum)
	}
}

// ── Prometheus metrics ────────────────────────────────────────────────────────

var (
	activeSlots = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tsm_queue_active_slots",
		Help: "Number of currently active (admitted) slots per tier.",
	}, []string{"tier"})

	totalAdmits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tsm_queue_admits_total",
		Help: "Total admitted requests per tier.",
	}, []string{"tier"})

	totalRejects = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tsm_queue_rejects_total",
		Help: "Total rejected requests per tier (capacity exceeded).",
	}, []string{"tier"})

	queueWaitSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tsm_queue_wait_seconds",
		Help:    "Time (seconds) a request waited before being admitted.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
	}, []string{"tier"})
)

// ── Tracker ───────────────────────────────────────────────────────────────────

// Tracker is the concurrency-limiting admission controller.
// It is safe for concurrent use from multiple goroutines.
type Tracker struct {
	mu     sync.Mutex
	active [3]int64 // indexed by Tier

	// limits[i] == 0 means unlimited for that tier
	limits [3]int64

	nextID atomic.Int64
}

// Stats is a point-in-time snapshot of queue state.
type Stats struct {
	GoldActive   int64 `json:"gold_active"`
	GoldLimit    int64 `json:"gold_limit"`
	SilverActive int64 `json:"silver_active"`
	SilverLimit  int64 `json:"silver_limit"`
	BronzeActive int64 `json:"bronze_active"`
	BronzeLimit  int64 `json:"bronze_limit"`
}

// NewTracker creates a tracker with the given per-tier concurrency limits.
// A limit of 0 means unlimited.
func NewTracker(goldLimit, silverLimit, bronzeLimit int64) *Tracker {
	return &Tracker{
		limits: [3]int64{goldLimit, silverLimit, bronzeLimit},
	}
}

// Admit attempts to obtain an admission slot for the given tier.
//
// Returns (slot, nil) on success.
// Returns (nil, ErrCapacityExceeded) if the tier's concurrency limit is full.
func (t *Tracker) Admit(tier Tier) (*Slot, error) {
	start := time.Now()

	t.mu.Lock()
	limit := t.limits[tier]
	if limit > 0 && t.active[tier] >= limit {
		t.mu.Unlock()
		totalRejects.WithLabelValues(tier.String()).Inc()
		return nil, fmt.Errorf("tier %s at capacity (%d/%d)", tier, t.active[tier], limit)
	}
	t.active[tier]++
	t.mu.Unlock()

	activeSlots.WithLabelValues(tier.String()).Inc()
	totalAdmits.WithLabelValues(tier.String()).Inc()
	queueWaitSeconds.WithLabelValues(tier.String()).Observe(time.Since(start).Seconds())

	id := fmt.Sprintf("slot-%d", t.nextID.Add(1))
	return &Slot{
		ID:        id,
		Tier:      tier.String(),
		AdmitTime: time.Now(),
		tracker:   t,
		tierEnum:  tier,
	}, nil
}

func (t *Tracker) release(tier Tier) {
	t.mu.Lock()
	if t.active[tier] > 0 {
		t.active[tier]--
	}
	t.mu.Unlock()
	activeSlots.WithLabelValues(tier.String()).Dec()
}

// Stats returns a snapshot of current queue state.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Stats{
		GoldActive:   t.active[TierGold],
		GoldLimit:    t.limits[TierGold],
		SilverActive: t.active[TierSilver],
		SilverLimit:  t.limits[TierSilver],
		BronzeActive: t.active[TierBronze],
		BronzeLimit:  t.limits[TierBronze],
	}
}
