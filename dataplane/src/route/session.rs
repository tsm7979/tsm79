/// Session-pinned deterministic routing — Gap 9 fix.
///
/// Problem: routing the same conversation to different backends on each turn
/// creates context fragmentation (cloud turn + local turn → incoherent context).
///
/// Solution: extract or mint a session ID from the request, then hash-pin
/// it to a specific backend for the lifetime of the conversation.
///
/// Backend selection:
///   - `local`  — on-prem model; used when session is flagged sensitive
///   - `cloud`  — upstream AI API (OpenAI / Anthropic / etc.)
///
/// Pin rules:
///   1. If session has ever been routed `local` → always `local` for that session.
///   2. If session is new AND first request is `Clean` → route `cloud`.
///   3. If session is new AND first request is flagged → route `local`.
///
/// The pin is stored in a fixed-size concurrent map.  Least-recently-used
/// entries are evicted when capacity is exceeded.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum number of concurrent session pins to keep in memory.
/// Each entry is ~128 bytes.  At 10_000 sessions = ~1.3 MB.
const MAX_SESSIONS: usize = 10_000;

/// How long an idle session pin is retained.
const SESSION_TTL: Duration = Duration::from_secs(3600 * 4); // 4 hours

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePin {
    /// Route all turns of this session through an on-prem model.
    Local,
    /// Route through the upstream cloud API.
    Cloud,
}

#[derive(Debug, Clone)]
struct PinEntry {
    pin:        RoutePin,
    last_seen:  Instant,
    turn_count: u32,
}

/// Thread-safe session routing table.
pub struct SessionRouter {
    inner: Mutex<SessionRouterInner>,
}

struct SessionRouterInner {
    table: HashMap<String, PinEntry>,
}

impl SessionRouter {
    pub fn new() -> Self {
        SessionRouter {
            inner: Mutex::new(SessionRouterInner {
                table: HashMap::with_capacity(MAX_SESSIONS / 2),
            }),
        }
    }

    /// Query and update the pin for `session_id`.
    ///
    /// `sensitive`: whether the CURRENT turn was detected as sensitive.
    ///
    /// Returns the authoritative pin for this session.
    /// Rule: once a session is pinned `Local`, it stays `Local` forever.
    pub fn route(&self, session_id: &str, sensitive: bool) -> RoutePin {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());

        // Evict stale sessions first (amortised — runs 1% of calls)
        if guard.table.len() >= MAX_SESSIONS {
            let now = Instant::now();
            guard.table.retain(|_, e| now.duration_since(e.last_seen) < SESSION_TTL);
            // If still over capacity, evict oldest entries
            if guard.table.len() >= MAX_SESSIONS {
                let mut entries: Vec<_> = guard.table.iter()
                    .map(|(k, e)| (k.clone(), e.last_seen))
                    .collect();
                entries.sort_unstable_by_key(|(_, t)| *t);
                for (k, _) in entries.iter().take(MAX_SESSIONS / 10) {
                    guard.table.remove(k);
                }
            }
        }

        let now = Instant::now();

        if let Some(entry) = guard.table.get_mut(session_id) {
            // Existing session
            entry.last_seen = now;
            entry.turn_count += 1;
            // Once pinned Local, never upgrade to Cloud
            if sensitive && entry.pin == RoutePin::Cloud {
                entry.pin = RoutePin::Local;
            }
            entry.pin
        } else {
            // New session: first turn determines the pin
            let pin = if sensitive { RoutePin::Local } else { RoutePin::Cloud };
            guard.table.insert(session_id.to_string(), PinEntry {
                pin,
                last_seen: now,
                turn_count: 1,
            });
            pin
        }
    }

    /// Explicitly revoke a session pin (e.g., on user logout / session end).
    pub fn revoke(&self, session_id: &str) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.table.remove(session_id);
    }

    /// Return current session count (for metrics).
    pub fn session_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).table.len()
    }
}

// ── Session ID extraction ─────────────────────────────────────────────────────

/// Extract or mint a session identifier from request headers and body.
///
/// Extraction precedence:
///   1. `X-TSM-Session-ID` header (explicit TSM session header)
///   2. `session_id` field in the JSON body (if present)
///   3. SHA-256(Authorization-header || path) — deterministic per-user session
///   4. Random UUID minted for this request (non-sticky, effectively no pinning)
pub fn extract_session_id(
    headers:    &[(Vec<u8>, Vec<u8>)],
    body:       &[u8],
    auth_token: &str,
    path:       &[u8],
) -> String {
    // 1. Explicit header
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(b"x-tsm-session-id") {
            if let Ok(s) = std::str::from_utf8(value) {
                let trimmed = s.trim();
                if !trimmed.is_empty() && trimmed.len() <= 128 {
                    return sanitize_session_id(trimmed);
                }
            }
        }
    }

    // 2. JSON body `session_id` field (OpenAI stream calls often carry this)
    if let Some(sid) = extract_json_session_id(body) {
        return sid;
    }

    // 3. Deterministic from auth + path (identifies a logical user session)
    if !auth_token.is_empty() {
        return derive_session_id(auth_token, path);
    }

    // 4. No identity signal — return a per-request ephemeral ID (no stickiness)
    format!("ephemeral-{}", pseudo_random_id())
}

/// Sanitize session ID: keep only alphanumeric, dash, underscore.
fn sanitize_session_id(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect()
}

/// Extract `"session_id"` from a JSON body without full deserialization.
fn extract_json_session_id(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    // Find `"session_id":"<value>"`
    let key = "\"session_id\"";
    let pos = text.find(key)?;
    let after = &text[pos + key.len()..];
    let colon_pos = after.find(':')? + 1;
    let value_part = after[colon_pos..].trim_start();
    if value_part.starts_with('"') {
        let end = value_part[1..].find('"')?;
        let sid = &value_part[1..=end];
        if sid.len() <= 128 {
            return Some(sanitize_session_id(sid));
        }
    }
    None
}

/// Derive a stable session ID from auth token + path using a fast hash.
fn derive_session_id(auth_token: &str, path: &[u8]) -> String {
    // FNV-1a 64-bit (no crypto needed — this is just for routing affinity)
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in auth_token.bytes().chain(b"|".iter().copied()).chain(path.iter().copied()) {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x00000100000001B3);
    }
    format!("derived-{:016x}", hash)
}

/// Pseudo-random ID from system time (not crypto-safe — used only for ephemeral sessions).
fn pseudo_random_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ (d.as_secs().wrapping_mul(0x9e3779b97f4a7c15)))
        .unwrap_or(0xdeadbeef)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_clean_session_routes_cloud() {
        let router = SessionRouter::new();
        let pin = router.route("sess-001", false);
        assert_eq!(pin, RoutePin::Cloud);
    }

    #[test]
    fn new_sensitive_session_routes_local() {
        let router = SessionRouter::new();
        let pin = router.route("sess-002", true);
        assert_eq!(pin, RoutePin::Local);
    }

    #[test]
    fn once_local_always_local() {
        let router = SessionRouter::new();
        router.route("sess-003", false); // clean → cloud
        router.route("sess-003", true);  // sensitive → upgrade to local
        let pin = router.route("sess-003", false); // subsequent clean → still local
        assert_eq!(pin, RoutePin::Local);
    }

    #[test]
    fn cloud_stays_cloud_when_clean() {
        let router = SessionRouter::new();
        router.route("sess-004", false);
        router.route("sess-004", false);
        let pin = router.route("sess-004", false);
        assert_eq!(pin, RoutePin::Cloud);
    }

    #[test]
    fn session_id_from_header() {
        let headers = vec![(b"X-TSM-Session-ID".to_vec(), b"my-session-123".to_vec())];
        let sid = extract_session_id(&headers, b"", "", b"/v1/chat");
        assert_eq!(sid, "my-session-123");
    }

    #[test]
    fn session_id_from_json_body() {
        let body = br#"{"model":"gpt-4","session_id":"abc-456","messages":[]}"#;
        let sid = extract_session_id(&[], body, "", b"/v1/chat");
        assert_eq!(sid, "abc-456");
    }

    #[test]
    fn session_id_derived_from_auth() {
        let sid = extract_session_id(&[], b"", "Bearer sk-test", b"/v1/chat");
        assert!(sid.starts_with("derived-"), "got: {}", sid);
    }

    #[test]
    fn revoke_removes_session() {
        let router = SessionRouter::new();
        router.route("sess-revoke", true);
        assert_eq!(router.session_count(), 1);
        router.revoke("sess-revoke");
        assert_eq!(router.session_count(), 0);
    }
}
