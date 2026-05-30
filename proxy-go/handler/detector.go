package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DetectionResult mirrors the Python detector's DetectResponse schema.
type DetectionResult struct {
	RiskScore    float64  `json:"risk_score"`
	Action       string   `json:"action"`        // allow | redact | block | route_local
	PIITypes     []string `json:"pii_types"`
	Severity     string   `json:"severity"`
	RedactedBody any      `json:"redacted_body"`
	PolicyRule   string   `json:"policy_rule"`
	LatencyMs    float64  `json:"latency_ms"`
}

// detectorClient calls the Python FastAPI detector service.
type detectorClient struct {
	url    string
	client *http.Client
}

func newDetectorClient(baseURL string) *detectorClient {
	return &detectorClient{
		url: baseURL,
		client: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        128,
				MaxIdleConnsPerHost: 64,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// Detect sends body to /detect and returns the result.
// On detector failure it fails open (allow with zero risk) so the proxy
// never blocks legitimate traffic due to infra issues.
//
// traceHeaders are forwarded verbatim so the detector participates in the
// distributed trace span (W3C traceparent, B3, Datadog, etc.).
func (d *detectorClient) Detect(ctx context.Context, body map[string]any, traceHeaders map[string]string) (DetectionResult, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return failOpen(), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url+"/detect", bytes.NewReader(payload))
	if err != nil {
		return failOpen(), nil
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range traceHeaders {
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return failOpen(), fmt.Errorf("detector unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return failOpen(), fmt.Errorf("detector returned %d", resp.StatusCode)
	}

	var result DetectionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return failOpen(), fmt.Errorf("detector decode: %w", err)
	}
	return result, nil
}

func failOpen() DetectionResult {
	return DetectionResult{
		RiskScore: 0,
		Action:    "allow",
		PIITypes:  []string{},
		Severity:  "none",
	}
}
