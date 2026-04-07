package handler

import (
	"os"
	"strconv"
	"sync"
	"time"
)

type cbState int

const (
	cbClosed cbState = iota // normal operation
	cbOpen                  // failing — reject all requests
	cbHalf                  // trial — let one through
)

type circuitBreaker struct {
	mu         sync.Mutex
	state      cbState
	failures   int
	lastFailed time.Time
	threshold  int
	timeout    time.Duration
}

var (
	cbMu      sync.RWMutex
	breakers  = make(map[string]*circuitBreaker)
	cbThresh  int
	cbTimeout time.Duration
)

func init() {
	cbThresh = 5
	if v := os.Getenv("TSM_CB_THRESHOLD"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			cbThresh = n
		}
	}
	cbTimeout = 30 * time.Second
	if v := os.Getenv("TSM_CB_TIMEOUT_MS"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			cbTimeout = time.Duration(n) * time.Millisecond
		}
	}
}

func getBreaker(upstream string) *circuitBreaker {
	cbMu.RLock()
	cb := breakers[upstream]
	cbMu.RUnlock()
	if cb != nil {
		return cb
	}
	cbMu.Lock()
	defer cbMu.Unlock()
	if cb = breakers[upstream]; cb != nil {
		return cb
	}
	cb = &circuitBreaker{threshold: cbThresh, timeout: cbTimeout}
	breakers[upstream] = cb
	return cb
}

// isAllowed returns true if the circuit is CLOSED or entering HALF state.
func isAllowed(upstream string) bool {
	cb := getBreaker(upstream)
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case cbClosed:
		return true
	case cbOpen:
		if time.Since(cb.lastFailed) > cb.timeout {
			cb.state = cbHalf
			return true
		}
		return false
	case cbHalf:
		return true
	}
	return true
}

func recordSuccess(upstream string) {
	cb := getBreaker(upstream)
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = cbClosed
}

func recordFailure(upstream string) {
	cb := getBreaker(upstream)
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailed = time.Now()
	if cb.failures >= cb.threshold {
		cb.state = cbOpen
	}
}

// breakerStatus returns a snapshot of all circuit breakers for the health endpoint.
func breakerStatus() map[string]string {
	cbMu.RLock()
	defer cbMu.RUnlock()
	out := make(map[string]string, len(breakers))
	for name, cb := range breakers {
		cb.mu.Lock()
		switch cb.state {
		case cbClosed:
			out[name] = "closed"
		case cbOpen:
			out[name] = "open"
		case cbHalf:
			out[name] = "half"
		}
		cb.mu.Unlock()
	}
	return out
}
