package handler

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	requestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tsm",
		Name:      "requests_total",
		Help:      "Total proxy requests by action and upstream.",
	}, []string{"action", "upstream"})

	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "tsm",
		Name:      "request_duration_seconds",
		Help:      "End-to-end proxy latency in seconds.",
		Buckets:   []float64{.001, .005, .010, .025, .050, .100, .250, .500, 1, 2.5, 5},
	}, []string{"action"})

	detectorDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "tsm",
		Name:      "detector_duration_seconds",
		Help:      "Time spent waiting for the Python detector.",
		Buckets:   []float64{.001, .002, .005, .010, .025, .050, .100, .250, .500},
	})

	fastPathHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tsm",
		Name:      "fastpath_hits_total",
		Help:      "Requests that hit the local fast-path PII scanner.",
	}, []string{"pii_type"})

	rateLimitedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "tsm",
		Name:      "rate_limited_total",
		Help:      "Requests rejected by the rate limiter.",
	})

	circuitOpenTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tsm",
		Name:      "circuit_open_total",
		Help:      "Requests rejected because the circuit breaker was open.",
	}, []string{"upstream"})

	piiTypesDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tsm",
		Name:      "pii_types_detected_total",
		Help:      "Count of PII type detections.",
	}, []string{"pii_type"})
)
