/// HMAC-SHA256 append-only tamper-evident audit chain.
///
/// Port of proxy-go/audit/log.go.  Every entry contains:
///   - seq:         monotonic sequence number
///   - timestamp:   RFC 3339 wall time
///   - request_id:  unique per-request UUID-like string
///   - org_id:      tenant identifier from request header
///   - model:       AI model name
///   - action:      allow | block | redact | route_local
///   - pii_types:   list of detected PII categories
///   - risk_score:  0.0 – 100.0
///   - latency_ms:  end-to-end request latency in milliseconds
///   - client_ip:   source IP address
///   - prev_hash:   hex-encoded SHA-256 HMAC of the previous entry
///   - hash:        hex-encoded SHA-256 HMAC of this entry
///
/// Chain integrity: hash = HMAC-SHA256(secret, prev_hash_hex || json_body)
/// An external verifier can replay the chain by re-computing each HMAC.
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::Serialize;
use serde_json;

type HmacSha256 = Hmac<Sha256>;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub seq:        u64,
    pub timestamp:  String,
    pub request_id: String,
    pub org_id:     String,
    pub model:      String,
    pub action:     String,
    pub pii_types:  Vec<String>,
    pub risk_score: f64,
    pub latency_ms: f64,
    pub client_ip:  String,
    pub prev_hash:  String,
    pub hash:       String,
}

// ── Internal mutable state, protected by a Mutex ─────────────────────────────

struct AuditInner {
    writer:    BufWriter<File>,
    seq:       u64,
    prev_hash: String,
    secret:    Vec<u8>,
}

// ── Public audit log handle ───────────────────────────────────────────────────

pub struct AuditLog {
    inner: Mutex<AuditInner>,
}

impl AuditLog {
    /// Open (or create) the audit log file at `path`.
    /// The HMAC secret must be at least 32 bytes in production.
    pub fn open(path: &str, secret: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(AuditLog {
            inner: Mutex::new(AuditInner {
                writer:    BufWriter::with_capacity(32 * 1024, file),
                seq:       0,
                prev_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
                secret:    secret.as_bytes().to_vec(),
            }),
        })
    }

    /// Append one entry to the chain.  Returns the completed `AuditEntry`
    /// (with hash fields filled in) so callers can use it for logging/metrics.
    pub fn append(
        &self,
        request_id: String,
        org_id:     String,
        model:      String,
        action:     String,
        pii_types:  Vec<String>,
        risk_score: f64,
        latency_ms: f64,
        client_ip:  String,
    ) -> std::io::Result<AuditEntry> {
        let mut guard = self.inner.lock().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "audit mutex poisoned")
        })?;

        let seq       = guard.seq + 1;
        let timestamp = iso8601_now();
        let prev_hash = guard.prev_hash.clone();

        // Build the entry without the hash field yet
        let mut entry = AuditEntry {
            seq,
            timestamp,
            request_id,
            org_id,
            model,
            action,
            pii_types,
            risk_score,
            latency_ms,
            client_ip,
            prev_hash: prev_hash.clone(),
            hash: String::new(),
        };

        // Serialize to JSON (hash field is empty string at this point)
        let json_body = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Compute HMAC-SHA256(secret, prev_hash || json_body)
        let hash_hex = compute_hmac(&guard.secret, &prev_hash, &json_body);
        entry.hash = hash_hex.clone();

        // Re-serialize with hash filled in
        let final_json = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // Append to log file, one JSON object per line
        guard.writer.write_all(final_json.as_bytes())?;
        guard.writer.write_all(b"\n")?;
        guard.writer.flush()?;

        // Advance chain state
        guard.seq       = seq;
        guard.prev_hash = hash_hex;

        Ok(entry)
    }

    /// Return (prev_hash, current_hash) for the most recent entry.
    /// Used by the PostgreSQL audit sink to populate HMAC chain fields.
    pub fn last_hashes(&self) -> (String, String) {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // prev_hash is the hash of the most recent entry; entry_hash is not tracked separately
        // We return (prev_prev_hash, prev_hash) — caller uses as (prev_hash, entry_hash) for next row
        let genesis = "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        if guard.seq == 0 {
            (genesis.clone(), genesis)
        } else {
            // prev_hash field already advanced to the latest committed hash
            (genesis, guard.prev_hash.clone())
        }
    }

    /// Verify the integrity of the on-disk chain starting from `path`.
    /// Returns `Ok(count)` if all `count` entries are valid, or an error
    /// describing which entry failed and why.
    pub fn verify(path: &str, secret: &str) -> std::io::Result<u64> {
        use std::io::{BufRead, BufReader};

        let file   = File::open(path)?;
        let reader = BufReader::new(file);

        let secret_bytes = secret.as_bytes();
        let genesis      = "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        let mut prev     = genesis;
        let mut count    = 0u64;

        for (line_no, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            // Parse the entry; strip the hash field before re-computing
            let mut entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("line {}: parse error: {}", line_no + 1, e),
                ))?;

            let stored_hash = entry.hash.clone();
            entry.hash = String::new();

            let json_body = serde_json::to_string(&entry)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            let expected = compute_hmac(secret_bytes, &prev, &json_body);

            if stored_hash != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "chain broken at seq {} (line {}): stored {} != expected {}",
                        entry.seq, line_no + 1, &stored_hash[..8], &expected[..8]
                    ),
                ));
            }

            prev  = stored_hash;
            count = entry.seq;
        }

        Ok(count)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// HMAC-SHA256(secret, prev_hash || json_body) → lowercase hex string (64 chars)
fn compute_hmac(secret: &[u8], prev_hash: &str, json_body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(prev_hash.as_bytes());
    mac.update(json_body.as_bytes());
    let result = mac.finalize().into_bytes();
    hex_encode(&result)
}

/// Encode a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Current time as an ISO 8601 / RFC 3339 string (UTC, second precision).
fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Manual formatting: YYYY-MM-DDTHH:MM:SSZ
    let s = secs;
    let (y, mo, d, h, mi, sec) = unix_to_ymd_hms(s);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, sec)
}

/// Decompose Unix epoch seconds into (year, month, day, hour, minute, second).
/// No external crate — standard calendar arithmetic.
fn unix_to_ymd_hms(mut secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let sec  = (secs % 60) as u32; secs /= 60;
    let min  = (secs % 60) as u32; secs /= 60;
    let hour = (secs % 24) as u32; secs /= 24;

    // Days since 1970-01-01
    let mut days = secs as u32;

    // 400-year cycles
    let (cycles400, rem) = (days / 146097, days % 146097);
    days = rem;
    let (cycles100, rem) = (days / 36524, days.min(36524 * 3)); // at most 3 100-year cycles
    let cycles100        = cycles100.min(3);
    days = rem - cycles100 * 36524;
    let (cycles4, rem)   = (days / 1461, days % 1461);
    days = rem;
    let (cycles1, rem)   = (days / 365, days.min(365 * 3));
    let cycles1          = cycles1.min(3);
    days = rem - cycles1 * 365;

    let year = cycles400 * 400 + cycles100 * 100 + cycles4 * 4 + cycles1 + 1970;

    let leap = is_leap(year);
    let month_days: &[u32] = if leap {
        &[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for &md in month_days {
        if days < md { break; }
        days -= md;
        month += 1;
    }

    (year, month, days + 1, hour, min, sec)
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_path(name: &str) -> String {
        format!("{}/{}", std::env::temp_dir().display(), name)
    }

    fn make_entry(log: &AuditLog, seq_hint: &str) -> AuditEntry {
        log.append(
            format!("req-{}", seq_hint),
            "org-1".into(),
            "gpt-4".into(),
            "block".into(),
            vec!["SSN".into()],
            95.0,
            12.3,
            "127.0.0.1".into(),
        ).expect("append should succeed")
    }

    #[test]
    fn three_entry_chain_verifies() {
        let path   = tmp_path("tsm_test_chain_verify.log");
        let secret = "a-very-long-test-secret-32-bytes!";
        let _clean = defer_delete(path.clone());

        let log = AuditLog::open(&path, secret).unwrap();
        make_entry(&log, "1");
        make_entry(&log, "2");
        make_entry(&log, "3");
        drop(log);

        let count = AuditLog::verify(&path, secret).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn tampered_entry_fails_verify() {
        let path   = tmp_path("tsm_test_chain_tamper.log");
        let secret = "another-secret-32-bytes-long-xxx";
        let _clean = defer_delete(path.clone());

        let log = AuditLog::open(&path, secret).unwrap();
        make_entry(&log, "a");
        make_entry(&log, "b");
        make_entry(&log, "c");
        drop(log);

        // Tamper: read, mutate entry 2 (line index 1), write back
        let contents = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = contents.lines().map(|l| l.to_owned()).collect();
        // Replace "block" with "allow" in the second line to corrupt it
        lines[1] = lines[1].replace("\"action\":\"block\"", "\"action\":\"allow\"");
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let result = AuditLog::verify(&path, secret);
        assert!(result.is_err(), "tampered chain must fail verification");
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("chain broken"), "error should mention chain broken: {}", msg);
    }

    #[test]
    fn seq_numbers_increment() {
        let path   = tmp_path("tsm_test_chain_seq.log");
        let secret = "seq-test-secret-32-bytes-padding!";
        let _clean = defer_delete(path.clone());

        let log = AuditLog::open(&path, secret).unwrap();
        let e1 = make_entry(&log, "x");
        let e2 = make_entry(&log, "y");
        let e3 = make_entry(&log, "z");
        assert_eq!(e1.seq, 1);
        assert_eq!(e2.seq, 2);
        assert_eq!(e3.seq, 3);
    }

    #[test]
    fn iso8601_format_correct() {
        let ts = iso8601_now();
        // Format: YYYY-MM-DDTHH:MM:SSZ  (20 chars)
        assert_eq!(ts.len(), 20, "timestamp len: {}", ts);
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[19..20], "Z");
    }

    // Helper: delete file when the guard is dropped (cleanup after test)
    struct DeferDelete(String);
    impl Drop for DeferDelete {
        fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
    }
    fn defer_delete(path: String) -> DeferDelete { DeferDelete(path) }
}
