package handler

import (
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// tokenBucket implements a per-IP token bucket rate limiter.
// Capacity = TSM_RATE_LIMIT (default 100) tokens, refilled at capacity/minute.
type tokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

var (
	rlMu     sync.Mutex
	rlBuckets = make(map[string]*tokenBucket, 4096)
	rlCap     float64
)

func init() {
	cap := 100
	if v := os.Getenv("TSM_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cap = n
		}
	}
	rlCap = float64(cap)
	// GC buckets that haven't been seen for 5 minutes.
	go func() {
		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()
		for range tick.C {
			evictStaleBuckets()
		}
	}()
}

// checkRateLimit returns true if the request is allowed, false if limited.
func checkRateLimit(ip string) bool {
	rlMu.Lock()
	defer rlMu.Unlock()

	now := time.Now()
	b, ok := rlBuckets[ip]
	if !ok {
		rlBuckets[ip] = &tokenBucket{tokens: rlCap - 1, lastSeen: now}
		return true
	}

	elapsed := now.Sub(b.lastSeen).Minutes()
	b.lastSeen = now
	b.tokens = math.Min(rlCap, b.tokens+elapsed*rlCap)

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func evictStaleBuckets() {
	cutoff := time.Now().Add(-5 * time.Minute)
	rlMu.Lock()
	defer rlMu.Unlock()
	for ip, b := range rlBuckets {
		if b.lastSeen.Before(cutoff) {
			delete(rlBuckets, ip)
		}
	}
}

// clientIP extracts the real IP respecting X-Forwarded-For.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		// Take the leftmost (client) IP.
		for i := 0; i < len(fwd); i++ {
			if fwd[i] == ',' {
				return fwd[:i]
			}
		}
		return fwd
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
