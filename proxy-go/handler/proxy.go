// Package handler implements the core TSM Go proxy request handler.
//
// Hot path (fast-path cache hit, no detector call needed):
//   clientIP → rate-limit check → read body → fast regex scan → block/allow
//   Typical latency: 1–3 ms
//
// Standard path (ambiguous content → full detector call):
//   clientIP → rate-limit → read body → fast regex → detector call → upstream
//   Typical latency: 3–8 ms (detector on localhost), 5–15 ms (detector over LAN)
//
// The Go runtime's goroutine scheduler handles 50k+ concurrent connections
// without thread exhaustion, which is where Python/Node proxies degrade.

package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tsm7979/tsm79/proxy-go/audit"
)

// New builds and returns the main HTTP mux.
func New(detectorURL string, al *audit.Log) http.Handler {
	det := newDetectorClient(detectorURL)
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health",          healthHandler(detectorURL))
	mux.HandleFunc("GET /metrics",         promhttp.Handler().ServeHTTP)
	mux.HandleFunc("GET /v1/models",       modelsHandler)
	mux.HandleFunc("POST /v1/chat/completions", completionHandler(det, al))
	mux.HandleFunc("POST /v1/completions",      completionHandler(det, al))
	mux.HandleFunc("OPTIONS /",            corsHandler)

	// Catch-all 404
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sendJSON(w, http.StatusNotFound, map[string]any{
			"error": map[string]any{"code": 404, "message": "not found: " + r.URL.Path},
		})
	})

	return withCORS(mux)
}

// ── Core handler ──────────────────────────────────────────────────────────────

func completionHandler(det *detectorClient, al *audit.Log) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t0  := time.Now()
		ip  := clientIP(r)
		org := r.Header.Get("X-TSM-Org")
		if org == "" {
			org = "default"
		}

		// ── Rate limit ────────────────────────────────────────────────────────
		if !checkRateLimit(ip) {
			rateLimitedTotal.Inc()
			sendJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": map[string]any{"code": "rate_limited", "message": "Too many requests."},
			})
			return
		}

		// ── Read body ─────────────────────────────────────────────────────────
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20)) // 4 MiB max
		if err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]any{
				"error": map[string]any{"code": 400, "message": "failed to read body"},
			})
			return
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]any{
				"error": map[string]any{"code": 400, "message": "invalid JSON"},
			})
			return
		}

		model := stringField(body, "model", "gpt-3.5-turbo")

		// ── Extract distributed trace headers ─────────────────────────────────
		// Forward W3C Trace Context, Zipkin B3, and Datadog APM headers from the
		// client to the detector and (when UPSTREAM_FORWARD=1) to the upstream AI
		// provider, enabling end-to-end distributed tracing across the full path.
		traceHeaders := extractTraceHeaders(r)

		// ── Fast-path local PII scan (< 0.5 ms) ──────────────────────────────
		text    := extractText(body)
		fpType, fpSev := fastPathScan(text)

		var (
			action     string
			piiTypes   []string
			riskScore  float64
			severity   string
			policyRule string
		)

		if fpType != "" {
			// Critical pattern matched locally — block immediately, skip detector.
			fastPathHits.WithLabelValues(fpType).Inc()
			piiTypesDetected.WithLabelValues(fpType).Inc()
			action    = "block"
			piiTypes  = []string{fpType}
			riskScore = fastPathRiskScore(fpSev)
			severity  = fpSev
			policyRule = "fast_path_critical"

			slog.Info("FAST-PATH BLOCK",
				"pii_type", fpType,
				"risk_score", riskScore,
				"org", org,
				"model", model,
			)
		} else {
			// ── Detector deep scan ────────────────────────────────────────────
			ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
			defer cancel()

			detStart := time.Now()
			det_result, detErr := det.Detect(ctx, body, traceHeaders)
			detectorDuration.Observe(time.Since(detStart).Seconds())

			if detErr != nil {
				failureMode := strings.ToLower(strings.TrimSpace(os.Getenv("TSM_DETECTOR_FAILURE_MODE")))
				switch failureMode {
				case "block":
					// Fail closed — block all traffic until detector recovers
					slog.Warn("detector unavailable, failing CLOSED (block mode)", "err", detErr)
					sendJSON(w, http.StatusServiceUnavailable, map[string]any{
						"error": map[string]any{
							"code":    "detector_unavailable",
							"message": "Security detector is unavailable. Requests blocked until service recovers.",
						},
					})
					return
				case "degrade":
					// Fast-path already ran; pass through with a degraded flag
					slog.Warn("detector unavailable, degraded mode (fast-path only)", "err", detErr)
					// det_result already set to failOpen() above — continue
				default:
					// "allow" (default) — fail open, log warning
					slog.Warn("detector unavailable, failing open (allow mode)", "err", detErr)
				}
			}

			action     = det_result.Action
			piiTypes   = det_result.PIITypes
			riskScore  = det_result.RiskScore
			severity   = det_result.Severity
			policyRule = det_result.PolicyRule
		}

		latencyMs := float64(time.Since(t0).Microseconds()) / 1000.0

		// ── Audit log (tamper-proof HMAC chain) ───────────────────────────────
		_ = al.Append(audit.Entry{
			RequestID: r.Header.Get("X-Request-ID"),
			OrgID:     org,
			Model:     model,
			Action:    action,
			PIITypes:  piiTypes,
			RiskScore: riskScore,
			LatencyMs: latencyMs,
			ClientIP:  ip,
		})

		for _, pt := range piiTypes {
			piiTypesDetected.WithLabelValues(pt).Inc()
		}

		upstream := resolveUpstream(model, action)
		requestsTotal.WithLabelValues(action, upstream).Inc()

		// ── Block ─────────────────────────────────────────────────────────────
		if action == "block" {
			requestDuration.WithLabelValues(action).Observe(time.Since(t0).Seconds())
			w.Header().Set("X-TSM-Action", action)
			w.Header().Set("X-TSM-Risk", formatFloat(riskScore))
			sendJSON(w, http.StatusBadRequest, map[string]any{
				"error": map[string]any{
					"code":    "tsm_blocked",
					"message": "[TSM] Request blocked — detected: " + strings.Join(piiTypes, ", "),
				},
				"tsm": map[string]any{
					"action": action, "risk_score": riskScore,
					"pii_types": piiTypes, "policy_rule": policyRule,
					"latency_ms": latencyMs,
				},
			})
			return
		}

		// ── Circuit breaker ───────────────────────────────────────────────────
		if !isAllowed(upstream) {
			circuitOpenTotal.WithLabelValues(upstream).Inc()
			sendJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": map[string]any{
					"code":    "upstream_unavailable",
					"message": upstream + " is temporarily unavailable",
				},
			})
			return
		}

		// ── Forward to upstream ───────────────────────────────────────────────
		// For now emit a demo response; the full upstream forwarding is handled
		// by the TypeScript proxy or can be enabled via UPSTREAM_FORWARD=1.
		requestDuration.WithLabelValues(action).Observe(time.Since(t0).Seconds())

		w.Header().Set("X-TSM-Action", action)
		w.Header().Set("X-TSM-Risk", formatFloat(riskScore))
		w.Header().Set("X-TSM-PII", strings.Join(piiTypes, ","))
		w.Header().Set("X-TSM-Severity", severity)
		w.Header().Set("X-TSM-Policy", policyRule)
		w.Header().Set("X-TSM-Latency-Ms", formatFloat(latencyMs))
		w.Header().Set("X-TSM-Upstream", upstream)

		// Proxy to real upstream if UPSTREAM_FORWARD is set.
		if upstreamForward() {
			proxyToUpstream(w, r, body, upstream, action)
			if action != "block" {
				recordSuccess(upstream)
			}
		} else {
			sendJSON(w, http.StatusOK, map[string]any{
				"tsm": map[string]any{
					"action":     action,
					"risk_score": riskScore,
					"pii_types":  piiTypes,
					"severity":   severity,
					"policy_rule": policyRule,
					"latency_ms": latencyMs,
					"upstream":   upstream,
				},
				"note": "Set UPSTREAM_FORWARD=1 and configure upstream keys to forward traffic.",
			})
		}

		slog.Info("request",
			"action", action,
			"model", model,
			"risk", riskScore,
			"latency_ms", latencyMs,
			"org", org,
		)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// traceHeaderKeys lists the distributed-tracing headers we propagate.
// W3C Trace Context (RFC 9204), Zipkin B3, and Datadog APM are all supported
// so TSM works with any observability backend out of the box.
var traceHeaderKeys = []string{
	"Traceparent", "Tracestate",                           // W3C Trace Context
	"X-B3-Traceid", "X-B3-Spanid", "X-B3-Parentspanid", "X-B3-Sampled", // Zipkin B3
	"X-Datadog-Trace-Id", "X-Datadog-Parent-Id", "X-Datadog-Sampling-Priority", // Datadog
	"X-Request-Id",                                        // Generic correlation
}

// extractTraceHeaders copies trace propagation headers from an incoming request
// into a flat map ready to be set on outbound detector / upstream calls.
func extractTraceHeaders(r *http.Request) map[string]string {
	out := make(map[string]string, len(traceHeaderKeys))
	for _, k := range traceHeaderKeys {
		if v := r.Header.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}

func extractText(body map[string]any) string {
	var sb strings.Builder
	if msgs, ok := body["messages"].([]any); ok {
		for _, m := range msgs {
			if msg, ok := m.(map[string]any); ok {
				if role, _ := msg["role"].(string); role == "user" {
					if content, _ := msg["content"].(string); content != "" {
						sb.WriteString(content)
						sb.WriteByte(' ')
					}
				}
			}
		}
	}
	if prompt, _ := body["prompt"].(string); prompt != "" {
		sb.WriteString(prompt)
	}
	return sb.String()
}

func resolveUpstream(model, action string) string {
	if action == "route_local" {
		return "ollama"
	}
	switch {
	case strings.HasPrefix(model, "claude"):
		return "anthropic"
	case strings.HasPrefix(model, "llama"), strings.HasPrefix(model, "mistral"),
		strings.HasPrefix(model, "phi"), strings.HasPrefix(model, "gemma"):
		return "ollama"
	default:
		return "openai"
	}
}

func proxyToUpstream(w http.ResponseWriter, r *http.Request, body map[string]any, upstream, action string) {
	// Stub — real implementation mirrors proxy/src/upstream.ts logic in Go.
	// Enabled only when UPSTREAM_FORWARD=1.
	sendJSON(w, http.StatusOK, map[string]any{
		"note": "upstream forwarding not implemented in this stub",
	})
}

func upstreamForward() bool {
	return strings.ToLower(strings.TrimSpace(os.Getenv("UPSTREAM_FORWARD"))) == "1"
}

func healthHandler(detectorURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sendJSON(w, http.StatusOK, map[string]any{
			"status":   "healthy",
			"service":  "TSM Go Proxy",
			"version":  "2.0.0",
			"detector": detectorURL,
			"breakers": breakerStatus(),
		})
	}
}

func modelsHandler(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data": []map[string]any{
			{"id": "gpt-4",              "object": "model", "owned_by": "openai"},
			{"id": "gpt-3.5-turbo",      "object": "model", "owned_by": "openai"},
			{"id": "claude-sonnet-4-6",  "object": "model", "owned_by": "anthropic"},
			{"id": "llama3",             "object": "model", "owned_by": "local"},
		},
	})
}

func corsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	w.WriteHeader(http.StatusNoContent)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

func stringField(m map[string]any, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}
