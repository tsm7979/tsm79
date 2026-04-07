// Package handler — fast-path local PII regex scanner.
//
// This runs BEFORE calling the Python detector for the most obvious high-risk
// patterns. Compiled regexp on typical AI prompts completes in < 0.5 ms, so
// the total round-trip stays under 5 ms for cache-warm requests.
//
// Patterns here are the CRITICAL-severity ones only. Ambiguous / context-
// dependent PII (names, addresses, DOBs) still goes to the full detector.

package handler

import (
	"regexp"
	"strings"
)

type fastMatch struct {
	piiType  string
	severity string
}

// fastPathScan returns the first critical PII type found, or ("", "").
// It is intentionally conservative: only fires on unambiguous patterns.
// False negatives go to the detector; false positives here would block clean traffic.
func fastPathScan(text string) (piiType, severity string) {
	for _, rule := range compiledFastRules {
		if rule.re.MatchString(text) {
			return rule.piiType, rule.severity
		}
	}
	return "", ""
}

type fastRule struct {
	re      *regexp.Regexp
	piiType string
	severity string
}

// compiledFastRules are pre-compiled at startup (zero allocation on hot path).
var compiledFastRules = []fastRule{
	// OpenAI key
	{re: regexp.MustCompile(`sk-[a-zA-Z0-9]{48}`), piiType: "API_KEY_OPENAI", severity: "critical"},
	// Anthropic key
	{re: regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{40,}`), piiType: "API_KEY_ANTHROPIC", severity: "critical"},
	// GitHub tokens (PAT / app / server-to-server)
	{re: regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}`), piiType: "API_KEY_GITHUB", severity: "critical"},
	// AWS access key
	{re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), piiType: "API_KEY_AWS", severity: "critical"},
	// SSN  xxx-xx-xxxx
	{re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), piiType: "SSN", severity: "critical"},
	// JWT (three base64url segments)
	{re: regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`), piiType: "JWT", severity: "high"},
	// Visa/MC credit card (16 digits, optional spaces/dashes)
	{re: regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b`), piiType: "CREDIT_CARD", severity: "high"},
	// Private key block
	{re: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`), piiType: "PRIVATE_KEY", severity: "critical"},
}

// riskScore returns a coarse risk score for fast-path hits.
func fastPathRiskScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 95
	case "high":
		return 70
	default:
		return 40
	}
}
