// Package audit provides a tamper-proof, HMAC-SHA256-chained append-only audit log.
//
// Chain structure:
//   Entry[0]: data=JSON, prev="genesis", mac=HMAC(secret, "genesis"+data)
//   Entry[N]: data=JSON, prev=mac[N-1],  mac=HMAC(secret, mac[N-1]+data)
//
// Verification:
//   Walk entries sequentially; recompute each mac and compare.
//   A single deleted or modified entry breaks every subsequent mac.
//   The log cannot be silently tampered without the HMAC secret.

package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is one immutable record in the audit chain.
type Entry struct {
	Seq        uint64         `json:"seq"`
	Timestamp  time.Time      `json:"ts"`
	RequestID  string         `json:"request_id"`
	OrgID      string         `json:"org_id"`
	Model      string         `json:"model"`
	Action     string         `json:"action"`     // allow | redact | block | route_local
	PIITypes   []string       `json:"pii_types"`
	RiskScore  float64        `json:"risk_score"`
	LatencyMs  float64        `json:"latency_ms"`
	Upstream   string         `json:"upstream"`
	ClientIP   string         `json:"client_ip"`
	Extra      map[string]any `json:"extra,omitempty"`
	PrevHash   string         `json:"prev_hash"`
	Hash       string         `json:"hash"`
}

// Log is the tamper-proof, append-only audit logger.
type Log struct {
	mu       sync.Mutex
	f        *os.File
	w        *bufio.Writer
	secret   []byte
	seq      uint64
	prevHash string
}

// New opens (or creates) an audit log file, reads the last entry to restore
// the chain head, and returns a ready-to-use Log.
func New(path, secret string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}

	al := &Log{
		f:        f,
		w:        bufio.NewWriterSize(f, 32*1024),
		secret:   []byte(secret),
		prevHash: "genesis",
	}

	// Restore chain head from last entry so we can continue an existing log.
	if last, ok := readLastEntry(f); ok {
		al.seq      = last.Seq + 1
		al.prevHash = last.Hash
	}

	return al, nil
}

// Append writes a new entry to the chain. Thread-safe.
func (al *Log) Append(e Entry) error {
	al.mu.Lock()
	defer al.mu.Unlock()

	e.Seq       = al.seq
	e.Timestamp = time.Now().UTC()
	e.PrevHash  = al.prevHash
	e.Hash      = ""   // clear before marshal

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}

	e.Hash    = computeMAC(al.secret, al.prevHash, data)
	al.prevHash = e.Hash
	al.seq++

	// Marshal again with the hash included.
	data, err = json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal final: %w", err)
	}

	if _, err = al.w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return al.w.Flush()
}

// Close flushes and closes the underlying file.
func (al *Log) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()
	if err := al.w.Flush(); err != nil {
		return err
	}
	return al.f.Close()
}

// Verify reads the entire log file and validates every HMAC in the chain.
// Returns the number of valid entries and the first error found (if any).
func Verify(path, secret string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	key      := []byte(secret)
	prevHash := "genesis"
	count    := 0

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MiB per line max
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return count, fmt.Errorf("audit: line %d unmarshal: %w", count+1, err)
		}

		// Recompute hash: marshal with Hash="" then MAC.
		saved := e.Hash
		e.Hash = ""
		data, _ := json.Marshal(e)
		expected := computeMAC(key, prevHash, data)

		if !hmac.Equal([]byte(expected), []byte(saved)) {
			return count, fmt.Errorf("audit: chain broken at seq %d (expected %s got %s)",
				e.Seq, expected[:8], saved[:8])
		}

		prevHash = saved
		count++
	}
	return count, scanner.Err()
}

// ── helpers ──────────────────────────────────────────────────────────────────

func computeMAC(secret []byte, prev string, data []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(prev))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// readLastEntry scans the file linearly to find the last non-empty JSON line.
func readLastEntry(f *os.File) (Entry, bool) {
	if _, err := f.Seek(0, 0); err != nil {
		return Entry{}, false
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	var last []byte
	for scanner.Scan() {
		if b := scanner.Bytes(); len(b) > 0 {
			last = make([]byte, len(b))
			copy(last, b)
		}
	}
	if len(last) == 0 {
		return Entry{}, false
	}
	var e Entry
	if err := json.Unmarshal(last, &e); err != nil {
		return Entry{}, false
	}
	return e, true
}
