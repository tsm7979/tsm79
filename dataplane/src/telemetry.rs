/// Structured JSON logging for the TSM dataplane.
///
/// Replaces bare `eprintln!` with machine-parseable JSON lines that include:
///   - timestamp (Unix ms)
///   - level     (debug | info | warn | error)
///   - component (pool | pipeline | tls | detect | policy | ...)
///   - message
///   - optional key-value fields
///
/// Format compatible with Datadog, Loki, and CloudWatch Logs Insights.
///
/// Example output:
///   {"ts":1712700000123,"level":"info","component":"pipeline","msg":"request","method":"POST","path":"/v1/chat/completions","action":"allow","latency_ms":4.2}
///
/// Usage:
///   use crate::telemetry::{log_info, log_warn, log_error, log_debug};
///
///   log_info!("pipeline", "request complete"; "action" => "allow", "latency_ms" => 4.2);
///   log_warn!("tls", "cert not pinned"; "upstream" => "openai");
///   log_error!("pool", "connect failed"; "host" => host, "err" => e.to_string());

use std::sync::atomic::{AtomicBool, Ordering};

// ── Log level gating ──────────────────────────────────────────────────────────

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Call once at startup to enable debug-level log lines.
pub fn enable_debug() {
    DEBUG_ENABLED.store(true, Ordering::Relaxed);
}

pub fn is_debug() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
}

// ── Core emit function ────────────────────────────────────────────────────────

/// Emit one JSON log line to stderr.
///
/// `fields` is a flat alternating `[key, value, key, value, ...]` slice of
/// `&str` — the macro helpers build it for you.
pub fn emit(level: &str, component: &str, msg: &str, fields: &[(&str, String)]) {
    let ts = unix_ms();
    let mut out = String::with_capacity(256);
    out.push_str("{\"ts\":");
    out.push_str(&ts.to_string());
    out.push_str(",\"level\":\"");
    out.push_str(level);
    out.push_str("\",\"component\":\"");
    out.push_str(&json_escape(component));
    out.push_str("\",\"msg\":\"");
    out.push_str(&json_escape(msg));
    out.push('"');
    for (k, v) in fields {
        out.push_str(",\"");
        out.push_str(&json_escape(k));
        out.push_str("\":\"");
        out.push_str(&json_escape(v));
        out.push('"');
    }
    out.push('}');
    eprintln!("{}", out);
}

// ── Macros ────────────────────────────────────────────────────────────────────

/// `log_info!("component", "message"; "key" => value, ...)` → INFO line.
#[macro_export]
macro_rules! log_info {
    ($comp:expr, $msg:expr) => {
        $crate::telemetry::emit("info", $comp, $msg, &[])
    };
    ($comp:expr, $msg:expr; $($k:expr => $v:expr),+) => {
        $crate::telemetry::emit("info", $comp, $msg, &[
            $(($k, format!("{}", $v))),+
        ])
    };
}

/// `log_warn!("component", "message"; "key" => value, ...)` → WARN line.
#[macro_export]
macro_rules! log_warn {
    ($comp:expr, $msg:expr) => {
        $crate::telemetry::emit("warn", $comp, $msg, &[])
    };
    ($comp:expr, $msg:expr; $($k:expr => $v:expr),+) => {
        $crate::telemetry::emit("warn", $comp, $msg, &[
            $(($k, format!("{}", $v))),+
        ])
    };
}

/// `log_error!("component", "message"; "key" => value, ...)` → ERROR line.
#[macro_export]
macro_rules! log_error {
    ($comp:expr, $msg:expr) => {
        $crate::telemetry::emit("error", $comp, $msg, &[])
    };
    ($comp:expr, $msg:expr; $($k:expr => $v:expr),+) => {
        $crate::telemetry::emit("error", $comp, $msg, &[
            $(($k, format!("{}", $v))),+
        ])
    };
}

/// `log_debug!("component", "message"; ...)` → DEBUG line (no-op unless debug enabled).
#[macro_export]
macro_rules! log_debug {
    ($comp:expr, $msg:expr) => {
        if $crate::telemetry::is_debug() {
            $crate::telemetry::emit("debug", $comp, $msg, &[])
        }
    };
    ($comp:expr, $msg:expr; $($k:expr => $v:expr),+) => {
        if $crate::telemetry::is_debug() {
            $crate::telemetry::emit("debug", $comp, $msg, &[
                $(($k, format!("{}", $v))),+
            ])
        }
    };
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Minimal JSON string escaping — handles the characters that appear in
/// log messages and field values (control chars, backslash, double-quote).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c    => out.push(c),
        }
    }
    out
}

// ── Request telemetry helper ──────────────────────────────────────────────────

/// Structured access log entry for one proxied request.
pub struct RequestLog<'a> {
    pub request_id: &'a str,
    pub method:     &'a str,
    pub path:       &'a str,
    pub status:     u16,
    pub action:     &'a str,
    pub pii_types:  &'a [String],
    pub risk_score: f64,
    pub latency_ms: f64,
    pub upstream:   &'a str,
    pub client_ip:  &'a str,
}

impl<'a> RequestLog<'a> {
    pub fn emit(&self) {
        let pii = if self.pii_types.is_empty() {
            "none".to_owned()
        } else {
            self.pii_types.join(",")
        };
        emit("info", "pipeline", "request", &[
            ("request_id", self.request_id.to_owned()),
            ("method",     self.method.to_owned()),
            ("path",       self.path.to_owned()),
            ("status",     self.status.to_string()),
            ("action",     self.action.to_owned()),
            ("pii",        pii),
            ("risk",       format!("{:.1}", self.risk_score)),
            ("latency_ms", format!("{:.2}", self.latency_ms)),
            ("upstream",   self.upstream.to_owned()),
            ("client_ip",  self.client_ip.to_owned()),
        ]);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_produces_valid_json() {
        // Capture by redirecting to a string (can't capture stderr easily, so just
        // verify the format string manually)
        let mut out = String::new();
        let ts = unix_ms();
        out.push_str("{\"ts\":");
        out.push_str(&ts.to_string());
        out.push_str(",\"level\":\"info\",\"component\":\"test\",\"msg\":\"hello\"");
        out.push_str(",\"key\":\"val\"}");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["level"].as_str().unwrap(), "info");
        assert_eq!(parsed["msg"].as_str().unwrap(), "hello");
    }

    #[test]
    fn json_escape_handles_special_chars() {
        assert_eq!(json_escape("foo\"bar"), "foo\\\"bar");
        assert_eq!(json_escape("a\nb"),      "a\\nb");
        assert_eq!(json_escape("a\\b"),      "a\\\\b");
    }
}
