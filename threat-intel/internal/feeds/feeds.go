// Package feeds provides threat intelligence feed collectors.
//
// Each feed implements the Feed interface and is polled on its own schedule.
//
// Feeds:
//   NVDFeed        — NIST NVD CVE API v2 (new + updated CVEs last 30 days)
//   CISAKEVFeed    — CISA Known Exploited Vulnerabilities catalog
//   AbuseIPDBFeed  — AbuseIPDB top 10K abusive IPs (API key required)
//   OTXFeed        — AlienVault OTX threat pulses (API key required)
//   TorExitFeed    — Tor Project exit node list (public, no key)
//   VPNFeed        — VPN provider exit nodes (public lists)
//   MITREFeed      — MITRE ATT&CK techniques + malware (TAXII 2.1)
//
// Poll intervals:
//   NVD:      every 2 hours  (rate limit: 5 req/30s without key, 50/30s with key)
//   CISA KEV: every 6 hours  (static catalog, low churn)
//   AbuseIPDB: every 1 hour  (fresh abuse reports)
//   OTX:      every 30 min   (near-real-time threat pulses)
//   Tor:      every 1 hour   (exit node list rotates)
//   VPN:      every 24 hours (stable)
//   MITRE:    every 12 hours (low churn)

package feeds

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/tsm-ai/threat-intel/internal/store"
)

// Feed is the interface every collector must implement.
type Feed interface {
	// Name returns the stable identifier for this feed.
	Name() string
	// Interval returns how often to poll.
	Interval() time.Duration
	// Poll fetches the latest data and writes it into db.
	// Returns the number of new/updated records.
	Poll(ctx context.Context, db *store.ThreatDB) (int, error)
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
	},
}

func getJSON(ctx context.Context, url, apiKey, apiKeyHeader string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "TSM-AI-Firewall/1.0 threat-intel")
	if apiKey != "" && apiKeyHeader != "" {
		req.Header.Set(apiKeyHeader, apiKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http get %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("http %d from %s: %s", resp.StatusCode, url, body)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

// ── NVD CVE Feed ─────────────────────────────────────────────────────────────
//
// Uses NVD CVE API v2: https://services.nvd.nist.gov/rest/json/cves/2.0
// Rate limits: 5 req/30s without API key, 50/30s with key.
// We fetch CVEs modified in the last 2 hours on each poll.

type NVDFeed struct {
	APIKey string
	Log    *zap.Logger
}

func (f *NVDFeed) Name() string           { return "nvd_cve" }
func (f *NVDFeed) Interval() time.Duration { return 2 * time.Hour }

func (f *NVDFeed) Poll(ctx context.Context, db *store.ThreatDB) (int, error) {
	// Fetch CVEs modified in last 2 hours
	now := time.Now().UTC()
	start := now.Add(-2 * time.Hour)
	url := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=%s&lastModEndDate=%s&resultsPerPage=500",
		start.Format("2006-01-02T15:04:05.000"),
		now.Format("2006-01-02T15:04:05.000"),
	)

	var result nvdResponse
	if err := getJSON(ctx, url, f.APIKey, "apiKey", &result); err != nil {
		return 0, fmt.Errorf("NVD poll: %w", err)
	}

	iocs := make([]store.IOCRecord, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		cve := v.CVE
		score := extractCVSSScore(cve)
		iocs = append(iocs, store.IOCRecord{
			Indicator:   cve.ID,
			Type:        "cve",
			ThreatScore: score,
			Source:      "nvd",
			Tags:        extractCVETags(cve),
			LastSeen:    time.Now(),
			TTLHours:    720, // 30 days
			Description: extractCVEDescription(cve),
		})
	}

	if err := db.BulkSetIOCs(ctx, iocs); err != nil {
		return 0, fmt.Errorf("NVD store: %w", err)
	}

	f.Log.Info("NVD poll complete", zap.Int("cves", len(iocs)))
	return len(iocs), nil
}

// NVD API v2 response types
type nvdResponse struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID          string `json:"id"`
	Published   string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CvssMetricV31 []struct {
			CvssData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		CvssMetricV30 []struct {
			CvssData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
		} `json:"cvssMetricV30"`
		CvssMetricV2 []struct {
			CvssData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags"`
	} `json:"references"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
}

func extractCVSSScore(cve nvdCVE) float64 {
	if len(cve.Metrics.CvssMetricV31) > 0 {
		return cve.Metrics.CvssMetricV31[0].CvssData.BaseScore / 10.0
	}
	if len(cve.Metrics.CvssMetricV30) > 0 {
		return cve.Metrics.CvssMetricV30[0].CvssData.BaseScore / 10.0
	}
	if len(cve.Metrics.CvssMetricV2) > 0 {
		return cve.Metrics.CvssMetricV2[0].CvssData.BaseScore / 10.0
	}
	return 0.5
}

func extractCVEDescription(cve nvdCVE) string {
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			if len(d.Value) > 500 {
				return d.Value[:500]
			}
			return d.Value
		}
	}
	return ""
}

func extractCVETags(cve nvdCVE) []string {
	tags := []string{}
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && strings.HasPrefix(d.Value, "CWE-") {
				tags = append(tags, d.Value)
			}
		}
	}
	return tags
}

// ── CISA KEV Feed ─────────────────────────────────────────────────────────────
//
// CISA Known Exploited Vulnerabilities catalog.
// Public JSON, no API key required.
// URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

type CISAKEVFeed struct {
	Log *zap.Logger
}

func (f *CISAKEVFeed) Name() string           { return "cisa_kev" }
func (f *CISAKEVFeed) Interval() time.Duration { return 6 * time.Hour }

func (f *CISAKEVFeed) Poll(ctx context.Context, db *store.ThreatDB) (int, error) {
	const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	var result struct {
		Vulnerabilities []struct {
			CveID           string `json:"cveID"`
			VulnerabilityName string `json:"vulnerabilityName"`
			DateAdded       string `json:"dateAdded"`
			RequiredAction  string `json:"requiredAction"`
			Product         string `json:"product"`
			VendorProject   string `json:"vendorProject"`
		} `json:"vulnerabilities"`
	}

	if err := getJSON(ctx, url, "", "", &result); err != nil {
		return 0, fmt.Errorf("CISA KEV poll: %w", err)
	}

	iocs := make([]store.IOCRecord, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		iocs = append(iocs, store.IOCRecord{
			Indicator:   v.CveID,
			Type:        "cve",
			ThreatScore: 0.9, // KEV = actively exploited → high score
			Source:      "cisa_kev",
			Tags:        []string{"actively-exploited", v.VendorProject},
			LastSeen:    time.Now(),
			TTLHours:    720,
			Description: v.VulnerabilityName + ": " + v.RequiredAction,
		})
	}

	if err := db.BulkSetIOCs(ctx, iocs); err != nil {
		return 0, fmt.Errorf("CISA KEV store: %w", err)
	}

	f.Log.Info("CISA KEV poll complete", zap.Int("entries", len(iocs)))
	return len(iocs), nil
}

// ── AbuseIPDB Feed ────────────────────────────────────────────────────────────
//
// Top 10K abusive IPs from AbuseIPDB.
// Requires API key: https://www.abuseipdb.com/api
// Endpoint: GET /api/v2/blacklist?limit=10000&confidenceMinimum=90

type AbuseIPDBFeed struct {
	APIKey string
	Log    *zap.Logger
}

func (f *AbuseIPDBFeed) Name() string           { return "abuseipdb" }
func (f *AbuseIPDBFeed) Interval() time.Duration { return time.Hour }

func (f *AbuseIPDBFeed) Poll(ctx context.Context, db *store.ThreatDB) (int, error) {
	if f.APIKey == "" {
		f.Log.Warn("AbuseIPDB API key not set, skipping")
		return 0, nil
	}

	const url = "https://api.abuseipdb.com/api/v2/blacklist?limit=10000&confidenceMinimum=90"
	var result struct {
		Data []struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			TotalReports         int    `json:"totalReports"`
			NumDistinctUsers     int    `json:"numDistinctUsers"`
		} `json:"data"`
	}

	if err := getJSON(ctx, url, f.APIKey, "Key", &result); err != nil {
		return 0, fmt.Errorf("AbuseIPDB poll: %w", err)
	}

	recs := make([]store.IPRecord, 0, len(result.Data))
	blockEntries := make([]store.BlocklistEntry, 0)

	for _, d := range result.Data {
		score := float64(d.AbuseConfidenceScore) / 100.0
		recs = append(recs, store.IPRecord{
			IP:          d.IPAddress,
			ThreatScore: score,
			Country:     d.CountryCode,
			Sources:     []string{"abuseipdb"},
			FirstSeen:   time.Now(),
			LastUpdated: time.Now(),
			TTL:         24,
		})
		// Block IPs with >95% confidence
		if d.AbuseConfidenceScore >= 95 {
			blockEntries = append(blockEntries, store.BlocklistEntry{
				IP:        d.IPAddress,
				Reason:    "abuseipdb",
				AddedAt:   time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			})
		}
	}

	if err := db.BulkSetIPs(ctx, recs); err != nil {
		return 0, fmt.Errorf("AbuseIPDB store IPs: %w", err)
	}

	// Write to XDP blocklist
	for _, entry := range blockEntries {
		if err := db.BlockIP(ctx, entry); err != nil {
			f.Log.Warn("failed to block IP", zap.String("ip", entry.IP), zap.Error(err))
		}
	}

	f.Log.Info("AbuseIPDB poll complete",
		zap.Int("ips", len(recs)),
		zap.Int("blocked", len(blockEntries)))
	return len(recs), nil
}

// ── AlienVault OTX Feed ───────────────────────────────────────────────────────
//
// AlienVault OTX (Open Threat Exchange) — subscribed pulses from your followed
// users and groups, plus the curated TSM threat subscription.
// Endpoint: https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50

type OTXFeed struct {
	APIKey string
	Log    *zap.Logger
}

func (f *OTXFeed) Name() string           { return "otx" }
func (f *OTXFeed) Interval() time.Duration { return 30 * time.Minute }

func (f *OTXFeed) Poll(ctx context.Context, db *store.ThreatDB) (int, error) {
	if f.APIKey == "" {
		f.Log.Warn("OTX API key not set, skipping")
		return 0, nil
	}

	const url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=1"
	var result struct {
		Results []struct {
			Name        string `json:"name"`
			ThreatScore float64 `json:"adversary"`
			Tags        []string `json:"tags"`
			Indicators  []struct {
				Indicator string `json:"indicator"`
				Type      string `json:"type"` // IPv4, domain, FileHash-MD5, CVE, etc.
			} `json:"indicators"`
		} `json:"results"`
	}

	if err := getJSON(ctx, url, f.APIKey, "X-OTX-API-KEY", &result); err != nil {
		return 0, fmt.Errorf("OTX poll: %w", err)
	}

	var ipRecs []store.IPRecord
	var iocRecs []store.IOCRecord
	count := 0

	for _, pulse := range result.Results {
		for _, ind := range pulse.Indicators {
			count++
			switch ind.Type {
			case "IPv4":
				ipRecs = append(ipRecs, store.IPRecord{
					IP:          ind.Indicator,
					ThreatScore: 0.75,
					Sources:     []string{"otx"},
					FirstSeen:   time.Now(),
					LastUpdated: time.Now(),
					TTL:         48,
				})
			case "domain", "hostname":
				iocRecs = append(iocRecs, store.IOCRecord{
					Indicator:   ind.Indicator,
					Type:        "domain",
					ThreatScore: 0.75,
					Source:      "otx",
					Tags:        pulse.Tags,
					LastSeen:    time.Now(),
					TTLHours:    48,
					Description: pulse.Name,
				})
			case "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256":
				iocRecs = append(iocRecs, store.IOCRecord{
					Indicator:   ind.Indicator,
					Type:        "hash",
					ThreatScore: 0.8,
					Source:      "otx",
					Tags:        pulse.Tags,
					LastSeen:    time.Now(),
					TTLHours:    168,
					Description: pulse.Name,
				})
			case "CVE":
				iocRecs = append(iocRecs, store.IOCRecord{
					Indicator:   ind.Indicator,
					Type:        "cve",
					ThreatScore: 0.85,
					Source:      "otx",
					Tags:        pulse.Tags,
					LastSeen:    time.Now(),
					TTLHours:    720,
					Description: pulse.Name,
				})
			}
		}
	}

	db.BulkSetIPs(ctx, ipRecs)   //nolint:errcheck
	db.BulkSetIOCs(ctx, iocRecs) //nolint:errcheck

	f.Log.Info("OTX poll complete", zap.Int("indicators", count))
	return count, nil
}

// ── Tor Exit Node Feed ────────────────────────────────────────────────────────
//
// The Tor Project publishes a plain-text list of exit node IPs.
// URL: https://check.torproject.org/torbulkexitlist (one IP per line)
// No API key required.

type TorExitFeed struct {
	Log *zap.Logger
}

func (f *TorExitFeed) Name() string           { return "tor_exit" }
func (f *TorExitFeed) Interval() time.Duration { return time.Hour }

func (f *TorExitFeed) Poll(ctx context.Context, db *store.ThreatDB) (int, error) {
	const url = "https://check.torproject.org/torbulkexitlist"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "TSM-AI-Firewall/1.0 threat-intel")

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Tor list fetch: %w", err)
	}
	defer resp.Body.Close()

	var ips []string
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 10*1024*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, line)
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("Tor list scan: %w", err)
	}

	if err := db.ReplaceTorSet(ctx, ips); err != nil {
		return 0, fmt.Errorf("Tor set replace: %w", err)
	}

	// Also write IP records and add to XDP blocklist
	recs := make([]store.IPRecord, len(ips))
	for i, ip := range ips {
		recs[i] = store.IPRecord{
			IP:          ip,
			ThreatScore: 0.7, // Tor itself isn't malicious, but high-risk for AI APIs
			IsTor:       true,
			Sources:     []string{"tor_exit"},
			FirstSeen:   time.Now(),
			LastUpdated: time.Now(),
			TTL:         2,
		}
	}
	db.BulkSetIPs(ctx, recs) //nolint:errcheck

	f.Log.Info("Tor exit feed updated", zap.Int("nodes", len(ips)))
	return len(ips), nil
}

// ── VPN Exit Node Feed ────────────────────────────────────────────────────────
//
// VPN exit node IPs from public lists (iplists.firehol.org).
// Aggregates multiple VPN provider ranges.

type VPNFeed struct {
	Log *zap.Logger
}

func (f *VPNFeed) Name() string           { return "vpn_exit" }
func (f *VPNFeed) Interval() time.Duration { return 24 * time.Hour }

func (f *VPNFeed) Poll(ctx context.Context, db *store.ThreatDB) (int, error) {
	// Multiple curated VPN/anonymizer IP lists
	lists := []string{
		"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
		"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
	}

	var allIPs []string
	for _, listURL := range lists {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "TSM-AI-Firewall/1.0 threat-intel")
		resp, err := httpClient.Do(req)
		if err != nil {
			f.Log.Warn("VPN list fetch failed", zap.String("url", listURL), zap.Error(err))
			continue
		}

		scanner := bufio.NewScanner(io.LimitReader(resp.Body, 20*1024*1024))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Accept both individual IPs and CIDRs
			allIPs = append(allIPs, line)
		}
		resp.Body.Close()
	}

	if err := db.ReplaceVPNSet(ctx, allIPs); err != nil {
		return 0, fmt.Errorf("VPN set replace: %w", err)
	}

	recs := make([]store.IPRecord, len(allIPs))
	for i, ip := range allIPs {
		// Strip CIDR suffix if present
		host := ip
		if idx := strings.Index(ip, "/"); idx != -1 {
			host = ip[:idx]
		}
		recs[i] = store.IPRecord{
			IP:          host,
			ThreatScore: 0.5,
			IsVPN:       true,
			Sources:     []string{"vpn_exit"},
			FirstSeen:   time.Now(),
			LastUpdated: time.Now(),
			TTL:         48,
		}
	}
	db.BulkSetIPs(ctx, recs) //nolint:errcheck

	f.Log.Info("VPN exit feed updated", zap.Int("ranges", len(allIPs)))
	return len(allIPs), nil
}

// ── MITRE ATT&CK Feed ─────────────────────────────────────────────────────────
//
// Fetches techniques and malware from the MITRE ATT&CK STIX bundle.
// Uses the enterprise matrix STIX JSON (no auth required).
// Focuses on techniques targeting AI/ML infrastructure.

type MITREFeed struct {
	Log *zap.Logger
}

func (f *MITREFeed) Name() string           { return "mitre_attack" }
func (f *MITREFeed) Interval() time.Duration { return 12 * time.Hour }

func (f *MITREFeed) Poll(ctx context.Context, db *store.ThreatDB) (int, error) {
	// ATT&CK Enterprise STIX bundle (MITRE publishes on GitHub)
	const url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "TSM-AI-Firewall/1.0 threat-intel")

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("MITRE ATT&CK fetch: %w", err)
	}
	defer resp.Body.Close()

	// Parse STIX bundle — we only need technique and malware objects
	var bundle struct {
		Objects []struct {
			Type         string   `json:"type"`
			ID           string   `json:"id"`
			Name         string   `json:"name"`
			Description  string   `json:"description"`
			ExternalRefs []struct {
				Source string `json:"source_name"`
				ID     string `json:"external_id"`
			} `json:"external_references"`
			KillChainPhases []struct {
				Phase string `json:"phase_name"`
			} `json:"kill_chain_phases"`
		} `json:"objects"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 200*1024*1024)).Decode(&bundle); err != nil {
		return 0, fmt.Errorf("MITRE bundle decode: %w", err)
	}

	var iocs []store.IOCRecord
	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" && obj.Type != "malware" && obj.Type != "tool" {
			continue
		}

		// Find the MITRE ATT&CK external ID (Txxxx or Sxxxx)
		var extID string
		for _, ref := range obj.ExternalRefs {
			if ref.Source == "mitre-attack" {
				extID = ref.ID
				break
			}
		}
		if extID == "" {
			continue
		}

		phases := make([]string, 0, len(obj.KillChainPhases))
		for _, kc := range obj.KillChainPhases {
			phases = append(phases, kc.Phase)
		}

		desc := obj.Description
		if len(desc) > 500 {
			desc = desc[:500]
		}

		iocs = append(iocs, store.IOCRecord{
			Indicator:   extID,
			Type:        obj.Type,
			ThreatScore: 0.6,
			Source:      "mitre_attack",
			Tags:        phases,
			LastSeen:    time.Now(),
			TTLHours:    720,
			Description: obj.Name + ": " + desc,
		})
	}

	if err := db.BulkSetIOCs(ctx, iocs); err != nil {
		return 0, fmt.Errorf("MITRE store: %w", err)
	}

	f.Log.Info("MITRE ATT&CK poll complete", zap.Int("techniques", len(iocs)))
	return len(iocs), nil
}

// ── AllFeeds returns the full list of configured feeds ────────────────────────

// Config holds API keys for feeds that require authentication.
type Config struct {
	NVDAPIKey      string
	AbuseIPDBKey   string
	OTXAPIKey      string
}

// AllFeeds instantiates all feed collectors with the given config.
func AllFeeds(cfg Config, log *zap.Logger) []Feed {
	return []Feed{
		&NVDFeed{APIKey: cfg.NVDAPIKey, Log: log},
		&CISAKEVFeed{Log: log},
		&AbuseIPDBFeed{APIKey: cfg.AbuseIPDBKey, Log: log},
		&OTXFeed{APIKey: cfg.OTXAPIKey, Log: log},
		&TorExitFeed{Log: log},
		&VPNFeed{Log: log},
		&MITREFeed{Log: log},
	}
}
