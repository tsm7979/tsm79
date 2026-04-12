/// Policy hot-reload from the TSM Control Plane.
///
/// Background thread behavior:
///   1. On startup: POST /nodes/register to announce this dataplane node.
///   2. Every 30 seconds: GET /config/policy with If-None-Match: <current_version>
///   3. If 200: parse new ruleset, call policy_engine.reload(rules), ACK with
///      PUT /nodes/{id}/policy-ack {"version": N}
///   4. If 304: no change, sleep.
///   5. If error: log + backoff, never crash the dataplane.
///
/// The dataplane continues operating with its last-known policy on any
/// control-plane connectivity failure.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::policy::PolicyEngine;

/// Spawn the hot-reload background thread.  Returns immediately.
pub fn start(config: Arc<Config>, policy: Arc<PolicyEngine>) {
    if config.control_plane_url.is_empty() {
        return; // control plane disabled
    }

    let url   = config.control_plane_url.clone();
    let node  = config.node_id.clone();
    let addr  = listen_addr_string(&config);

    std::thread::Builder::new()
        .name("tsm-policy-hotreload".to_owned())
        .spawn(move || run_reload_loop(url, node, addr, policy))
        .ok();
}

fn listen_addr_string(config: &Config) -> String {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_owned());
    format!("{}:{}", host, config.listen_addr.port())
}

fn run_reload_loop(
    cp_url:  String,
    node_id: String,
    addr:    String,
    policy:  Arc<PolicyEngine>,
) {
    let host_port = parse_host_port(&cp_url);

    // ── Register with control plane ───────────────────────────────────────────
    let mut current_version: i64 = 0;
    let body = format!(
        r#"{{"id":"{node_id}","role":"dataplane","addr":"{addr}","health_path":"/api/health"}}"#,
    );
    if let Some(resp) = http_post(&host_port, "/nodes/register", &body) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
            current_version = v["policy_version"].as_i64().unwrap_or(0);
        }
        crate::telemetry::emit("info", "hotreload", "registered with control plane", &[
            ("node_id", node_id.clone()),
            ("addr",    addr.clone()),
            ("policy_version", current_version.to_string()),
        ]);
    } else {
        crate::telemetry::emit("warn", "hotreload", "control plane unreachable at startup", &[
            ("url", cp_url.clone()),
        ]);
    }

    // ── Poll loop ─────────────────────────────────────────────────────────────
    loop {
        std::thread::sleep(Duration::from_secs(30));

        let path = "/config/policy";
        match http_get_conditional(&host_port, path, current_version) {
            PollResult::NotModified => {
                // policy unchanged — nothing to do
            }
            PollResult::Updated { version, rules_json } => {
                crate::telemetry::emit("info", "hotreload", "policy updated", &[
                    ("version", version.to_string()),
                    ("rules",   rules_json.len().to_string()),
                ]);
                policy.reload_from_json(&rules_json);
                current_version = version;
                // ACK
                let ack = format!(r#"{{"version":{version}}}"#);
                http_put(&host_port, &format!("/nodes/{node_id}/policy-ack"), &ack);
            }
            PollResult::Error(e) => {
                crate::telemetry::emit("warn", "hotreload", "policy poll failed", &[
                    ("err", e),
                ]);
                // Backoff then retry — never crash
                std::thread::sleep(Duration::from_secs(30));
            }
        }
    }
}

// ── HTTP helpers (raw TCP, no dep) ─────────────────────────────────────────────

enum PollResult {
    NotModified,
    Updated { version: i64, rules_json: String },
    Error(String),
}

fn parse_host_port(url: &str) -> String {
    url.trim_start_matches("http://")
       .trim_start_matches("https://")
       .split('/')
       .next()
       .unwrap_or("localhost:9090")
       .to_owned()
}

fn http_get_conditional(host_port: &str, path: &str, etag: i64) -> PollResult {
    let mut stream = match TcpStream::connect(host_port) {
        Ok(s)  => s,
        Err(e) => return PollResult::Error(e.to_string()),
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_port}\r\nIf-None-Match: {etag}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return PollResult::Error("write failed".to_owned());
    }

    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let resp = String::from_utf8_lossy(&buf);

    // Status line: "HTTP/1.1 200 OK"
    let status = resp.lines().next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    match status {
        304 => PollResult::NotModified,
        200 => {
            // Find body after \r\n\r\n
            let body = resp.find("\r\n\r\n")
                .map(|i| &resp[i + 4..])
                .unwrap_or("")
                .trim()
                .to_owned();
            // Extract version from ETag header
            let version = resp.lines()
                .find(|l| l.to_lowercase().starts_with("etag:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse::<i64>().ok())
                .unwrap_or(0);
            PollResult::Updated { version, rules_json: body }
        }
        _ => PollResult::Error(format!("unexpected status {status}")),
    }
}

fn http_post(host_port: &str, path: &str, body: &str) -> Option<String> {
    let mut stream = TcpStream::connect(host_port).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let resp = String::from_utf8_lossy(&buf).to_string();
    resp.find("\r\n\r\n").map(|i| resp[i + 4..].trim().to_owned())
}

fn http_put(host_port: &str, path: &str, body: &str) {
    if let Ok(mut stream) = TcpStream::connect(host_port) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let req = format!(
            "PUT {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len(),
        );
        let _ = stream.write_all(req.as_bytes());
    }
}
