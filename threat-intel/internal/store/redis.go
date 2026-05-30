// Package store provides the Redis-backed threat intelligence database.
//
// Data model:
//   tsm:intel:ip:<ip>          → JSON blob  (IP reputation + TTL)
//   tsm:intel:ioc:<indicator>  → JSON blob  (IOC record + TTL)
//   tsm:intel:tor              → Redis SET  (Tor exit node IPs)
//   tsm:intel:vpn              → Redis SET  (known VPN exit IPs)
//   tsm:xdp:blocklist          → Redis HASH (ip → reason + expiry)
//   tsm:stats:feeds            → Redis HASH (feed_name → last_poll_unix)
//
// XDP blocklist update:
//   The Rust dataplane and the C eBPF loader both watch tsm:xdp:blocklist.
//   This service writes; the loaders read and program the kernel map.

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// IPRecord holds reputation data for a single IPv4/IPv6 address.
type IPRecord struct {
	IP          string    `json:"ip"`
	ThreatScore float64   `json:"threat_score"` // 0.0–1.0
	IsTor       bool      `json:"is_tor"`
	IsVPN       bool      `json:"is_vpn"`
	ASN         uint32    `json:"asn"`
	Country     string    `json:"country"`
	Sources     []string  `json:"sources"` // which feeds flagged this
	FirstSeen   time.Time `json:"first_seen"`
	LastUpdated time.Time `json:"last_updated"`
	TTL         int64     `json:"ttl_hours"`
}

// IOCRecord holds one Indicator of Compromise.
type IOCRecord struct {
	Indicator    string    `json:"indicator"`      // IP, domain, hash, CVE
	Type         string    `json:"type"`           // ip | domain | hash | cve
	ThreatScore  float64   `json:"threat_score"`
	Source       string    `json:"source"`
	Tags         []string  `json:"tags"`
	LastSeen     time.Time `json:"last_seen"`
	TTLHours     int       `json:"ttl_hours"`
	Description  string    `json:"description"`
}

// BlocklistEntry is a single entry in the XDP kernel blocklist.
type BlocklistEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"` // tor | vpn | botnet | abuseipdb | manual
	AddedAt   time.Time `json:"added_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// FeedStats tracks per-feed polling metadata.
type FeedStats struct {
	FeedName     string    `json:"feed_name"`
	LastPollAt   time.Time `json:"last_poll_at"`
	RecordCount  int       `json:"record_count"`
	ErrorCount   int       `json:"error_count"`
	LastErrorMsg string    `json:"last_error_msg,omitempty"`
}

// ── Client ────────────────────────────────────────────────────────────────────

const (
	keyIPPrefix        = "tsm:intel:ip:"
	keyIOCPrefix       = "tsm:intel:ioc:"
	keyTorSet          = "tsm:intel:tor"
	keyVPNSet          = "tsm:intel:vpn"
	keyXDPBlocklist    = "tsm:xdp:blocklist"
	keyFeedStats       = "tsm:stats:feeds"

	defaultIPTTL  = 24 * time.Hour
	defaultIOCTTL = 48 * time.Hour
)

// ThreatDB is the Redis-backed threat intelligence store.
type ThreatDB struct {
	rdb *redis.Client
	log *zap.Logger
}

// New creates a new ThreatDB from a Redis address (host:port).
func New(redisAddr, password string, db int, log *zap.Logger) (*ThreatDB, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Password:     password,
		DB:           db,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     20,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}

	return &ThreatDB{rdb: rdb, log: log}, nil
}

// Close shuts down the Redis connection pool.
func (t *ThreatDB) Close() error { return t.rdb.Close() }

// ── IP reputation ─────────────────────────────────────────────────────────────

// SetIP writes or updates an IP reputation record.
func (t *ThreatDB) SetIP(ctx context.Context, rec IPRecord) error {
	rec.LastUpdated = time.Now()
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	ttl := time.Duration(rec.TTL) * time.Hour
	if ttl <= 0 {
		ttl = defaultIPTTL
	}
	key := keyIPPrefix + rec.IP
	return t.rdb.Set(ctx, key, data, ttl).Err()
}

// GetIP returns the reputation record for an IP, or nil if not found.
func (t *ThreatDB) GetIP(ctx context.Context, ip string) (*IPRecord, error) {
	data, err := t.rdb.Get(ctx, keyIPPrefix+ip).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec IPRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// BulkSetIPs writes multiple IP records in a pipeline (efficient batch insert).
func (t *ThreatDB) BulkSetIPs(ctx context.Context, recs []IPRecord) error {
	if len(recs) == 0 {
		return nil
	}
	pipe := t.rdb.Pipeline()
	for _, rec := range recs {
		rec.LastUpdated = time.Now()
		data, err := json.Marshal(rec)
		if err != nil {
			t.log.Warn("marshal error", zap.String("ip", rec.IP), zap.Error(err))
			continue
		}
		ttl := time.Duration(rec.TTL) * time.Hour
		if ttl <= 0 {
			ttl = defaultIPTTL
		}
		pipe.Set(ctx, keyIPPrefix+rec.IP, data, ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// ── IOC store ─────────────────────────────────────────────────────────────────

// SetIOC writes an Indicator of Compromise.
func (t *ThreatDB) SetIOC(ctx context.Context, ioc IOCRecord) error {
	data, err := json.Marshal(ioc)
	if err != nil {
		return err
	}
	ttl := time.Duration(ioc.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = defaultIOCTTL
	}
	return t.rdb.Set(ctx, keyIOCPrefix+ioc.Indicator, data, ttl).Err()
}

// GetIOC looks up a single IOC indicator.
func (t *ThreatDB) GetIOC(ctx context.Context, indicator string) (*IOCRecord, error) {
	data, err := t.rdb.Get(ctx, keyIOCPrefix+indicator).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ioc IOCRecord
	if err := json.Unmarshal(data, &ioc); err != nil {
		return nil, err
	}
	return &ioc, nil
}

// BulkSetIOCs writes multiple IOC records in a pipeline.
func (t *ThreatDB) BulkSetIOCs(ctx context.Context, iocs []IOCRecord) error {
	if len(iocs) == 0 {
		return nil
	}
	pipe := t.rdb.Pipeline()
	for _, ioc := range iocs {
		data, err := json.Marshal(ioc)
		if err != nil {
			continue
		}
		ttl := time.Duration(ioc.TTLHours) * time.Hour
		if ttl <= 0 {
			ttl = defaultIOCTTL
		}
		pipe.Set(ctx, keyIOCPrefix+ioc.Indicator, data, ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// ── Tor / VPN sets ────────────────────────────────────────────────────────────

// ReplaceTorSet atomically replaces the entire Tor exit node set.
// Uses MULTI/EXEC + RENAME for atomic swap.
func (t *ThreatDB) ReplaceTorSet(ctx context.Context, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	tmp := keyTorSet + ":tmp"
	pipe := t.rdb.TxPipeline()
	pipe.Del(ctx, tmp)
	// Build the set members
	members := make([]interface{}, len(ips))
	for i, ip := range ips {
		members[i] = ip
	}
	pipe.SAdd(ctx, tmp, members...)
	pipe.Rename(ctx, tmp, keyTorSet)
	_, err := pipe.Exec(ctx)
	return err
}

// IsTor checks if an IP is a known Tor exit node.
func (t *ThreatDB) IsTor(ctx context.Context, ip string) (bool, error) {
	return t.rdb.SIsMember(ctx, keyTorSet, ip).Result()
}

// ReplaceVPNSet atomically replaces the VPN exit node set.
func (t *ThreatDB) ReplaceVPNSet(ctx context.Context, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	tmp := keyVPNSet + ":tmp"
	pipe := t.rdb.TxPipeline()
	pipe.Del(ctx, tmp)
	members := make([]interface{}, len(ips))
	for i, ip := range ips {
		members[i] = ip
	}
	pipe.SAdd(ctx, tmp, members...)
	pipe.Rename(ctx, tmp, keyVPNSet)
	_, err := pipe.Exec(ctx)
	return err
}

// ── XDP blocklist ─────────────────────────────────────────────────────────────

// BlockIP adds an IP to the XDP kernel blocklist with a reason and TTL.
// The eBPF loader watches this hash and syncs to the kernel map.
func (t *ThreatDB) BlockIP(ctx context.Context, entry BlocklistEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	ttl := time.Until(entry.ExpiresAt)
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	pipe := t.rdb.Pipeline()
	pipe.HSet(ctx, keyXDPBlocklist, entry.IP, data)
	// Mirror as a standalone key with TTL so it auto-expires from the hash too
	// (Redis HASH entries don't auto-expire; we expire via the standalone key).
	pipe.Set(ctx, "tsm:xdp:bl:"+entry.IP, "1", ttl)
	_, err = pipe.Exec(ctx)
	return err
}

// UnblockIP removes an IP from the XDP blocklist.
func (t *ThreatDB) UnblockIP(ctx context.Context, ip string) error {
	pipe := t.rdb.Pipeline()
	pipe.HDel(ctx, keyXDPBlocklist, ip)
	pipe.Del(ctx, "tsm:xdp:bl:"+ip)
	_, err := pipe.Exec(ctx)
	return err
}

// GetBlocklist returns all currently blocked IPs.
func (t *ThreatDB) GetBlocklist(ctx context.Context) ([]BlocklistEntry, error) {
	data, err := t.rdb.HGetAll(ctx, keyXDPBlocklist).Result()
	if err != nil {
		return nil, err
	}
	entries := make([]BlocklistEntry, 0, len(data))
	for ip, blob := range data {
		// Check if the TTL key still exists; if not, this entry is expired
		exists, _ := t.rdb.Exists(ctx, "tsm:xdp:bl:"+ip).Result()
		if exists == 0 {
			// Auto-evict from hash
			t.rdb.HDel(ctx, keyXDPBlocklist, ip) //nolint:errcheck
			continue
		}
		var entry BlocklistEntry
		if err := json.Unmarshal([]byte(blob), &entry); err == nil {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// BlocklistSize returns the number of entries in the XDP blocklist.
func (t *ThreatDB) BlocklistSize(ctx context.Context) (int64, error) {
	return t.rdb.HLen(ctx, keyXDPBlocklist).Result()
}

// ── Feed stats ────────────────────────────────────────────────────────────────

// RecordFeedPoll records a feed polling event.
func (t *ThreatDB) RecordFeedPoll(ctx context.Context, stats FeedStats) error {
	data, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	return t.rdb.HSet(ctx, keyFeedStats, stats.FeedName, data).Err()
}

// GetFeedStats returns stats for all feeds.
func (t *ThreatDB) GetFeedStats(ctx context.Context) ([]FeedStats, error) {
	data, err := t.rdb.HGetAll(ctx, keyFeedStats).Result()
	if err != nil {
		return nil, err
	}
	stats := make([]FeedStats, 0, len(data))
	for _, blob := range data {
		var s FeedStats
		if err := json.Unmarshal([]byte(blob), &s); err == nil {
			stats = append(stats, s)
		}
	}
	return stats, nil
}

// TorSetSize returns the number of known Tor exit nodes.
func (t *ThreatDB) TorSetSize(ctx context.Context) (int64, error) {
	return t.rdb.SCard(ctx, keyTorSet).Result()
}

// Ping verifies the Redis connection is alive.
func (t *ThreatDB) Ping(ctx context.Context) error {
	return t.rdb.Ping(ctx).Err()
}
