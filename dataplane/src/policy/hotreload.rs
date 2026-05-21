/// Policy hot-reload from the TSM Control Plane.
///
/// Background thread behavior:
///   1. On startup: POST /nodes/register to announce this dataplane node.
///   2. Every 30 seconds: GET /config/policy with If-None-Match: <current_version>
///   3. If 200: parse new ruleset, verify Ed25519 signature, call
///      policy_engine.reload(rules), ACK with PUT /nodes/{id}/policy-ack
///   4. If 304: no change, sleep.
///   5. If error: log + backoff, never crash the dataplane.
///
/// Signature verification:
///   The control plane sets `X-TSM-Policy-Signature: <base64(sig)>` and
///   `X-TSM-Policy-PubKey: <base64(32-byte raw Ed25519 public key)>` on every
///   200 response.  The dataplane verifies Ed25519(sig, body) using the pinned
///   public key before calling reload().
///
///   Public key bootstrap: the first key seen in `X-TSM-Policy-PubKey` is
///   pinned in memory for the lifetime of the process.  Override at startup
///   with `TSM_POLICY_PUBKEY_B64` env var (base64 of 32-byte raw Ed25519 key).
///   If neither is set, the signature check is skipped and a warning is emitted.
///
/// The dataplane continues operating with its last-known policy on any
/// control-plane connectivity failure or signature mismatch.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ring::signature::{self, UnparsedPublicKey};

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

    // Seed the pinned public key from the env var if set.
    // The thread will also bootstrap it from X-TSM-Policy-PubKey on first response.
    let pinned_pubkey: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(
        std::env::var("TSM_POLICY_PUBKEY_B64")
            .ok()
            .and_then(|b64| base64_decode_simple(&b64).ok()),
    ));

    std::thread::Builder::new()
        .name("tsm-policy-hotreload".to_owned())
        .spawn(move || run_reload_loop(url, node, addr, policy, pinned_pubkey))
        .ok();
}

fn listen_addr_string(config: &Config) -> String {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "localhost".to_owned());
    format!("{}:{}", host, config.listen_addr.port())
}

fn run_reload_loop(
    cp_url:        String,
    node_id:       String,
    addr:          String,
    policy:        Arc<PolicyEngine>,
    pinned_pubkey: Arc<Mutex<Option<Vec<u8>>>>,
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
            PollResult::Updated { version, body_bytes, sig_b64, pubkey_b64 } => {

                // ── Bootstrap / pin the public key ────────────────────────────
                // Accept the first key we see and pin it for the process lifetime.
                // Subsequent responses must use the same key.
                if let Some(ref kb64) = pubkey_b64 {
                    let mut pin = pinned_pubkey.lock().unwrap();
                    if pin.is_none() {
                        match base64_decode_simple(kb64) {
                            Ok(pk) if pk.len() == 32 => {
                                crate::telemetry::emit("info", "hotreload",
                                    "pinned control plane public key", &[
                                    ("pub_key_b64", kb64.clone()),
                                ]);
                                *pin = Some(pk);
                            }
                            _ => {
                                crate::telemetry::emit("warn", "hotreload",
                                    "X-TSM-Policy-PubKey is malformed — ignoring", &[]);
                            }
                        }
                    }
                }

                // ── Verify Ed25519 signature ──────────────────────────────────
                let pin = pinned_pubkey.lock().unwrap().clone();
                match pin {
                    None => {
                        // No public key available — warn and apply anyway.
                        // This allows unverified operation if the env var was
                        // never set and the control plane is not yet emitting keys.
                        crate::telemetry::emit("warn", "hotreload",
                            "no policy signing key pinned — applying unverified policy update", &[
                            ("version", version.to_string()),
                        ]);
                    }
                    Some(ref pub_bytes) => {
                        // We have a pinned key — a missing or bad signature is fatal.
                        match sig_b64 {
                            None => {
                                crate::telemetry::emit("error", "hotreload",
                                    "policy update rejected: no signature from control plane", &[
                                    ("version", version.to_string()),
                                ]);
                                continue; // skip this update
                            }
                            Some(ref sb64) => {
                                match verify_ed25519(pub_bytes, &body_bytes, sb64) {
                                    Ok(()) => {
                                        crate::telemetry::emit("info", "hotreload",
                                            "policy signature verified", &[
                                            ("version", version.to_string()),
                                        ]);
                                    }
                                    Err(e) => {
                                        crate::telemetry::emit("error", "hotreload",
                                            "policy update REJECTED: signature verification failed", &[
                                            ("version", version.to_string()),
                                            ("err",     e),
                                        ]);
                                        continue; // drop this update — do not apply
                                    }
                                }
                            }
                        }
                    }
                }

                // ── Apply verified policy ─────────────────────────────────────
                let rules_json = String::from_utf8_lossy(&body_bytes).into_owned();
                crate::telemetry::emit("info", "hotreload", "policy updated", &[
                    ("version", version.to_string()),
                    ("bytes",   body_bytes.len().to_string()),
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
    Updated {
        version:    i64,
        body_bytes: Vec<u8>,  // raw body bytes — signed over by the control plane
        sig_b64:    Option<String>,
        pubkey_b64: Option<String>,
    },
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

    // Split raw bytes at the first \r\n\r\n into header section and body.
    // We operate on raw bytes so the body slice matches exactly what the
    // control plane signed (json.Marshal output — no trailing whitespace assumed,
    // but we trim anyway since HTTP may add \n at end of body).
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let (header_bytes, body_bytes) = match header_end {
        Some(pos) => (&buf[..pos], buf[pos + 4..].to_vec()),
        None      => (&buf[..], Vec::new()),
    };
    let header_str = String::from_utf8_lossy(header_bytes);

    // Status line: "HTTP/1.1 200 OK"
    let status = header_str.lines().next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    match status {
        304 => PollResult::NotModified,
        200 => {
            // Extract version from ETag header
            let version = header_str.lines()
                .find(|l| l.to_lowercase().starts_with("etag:"))
                .and_then(|l| l.splitn(2, ':').nth(1))
                .and_then(|v| v.trim().parse::<i64>().ok())
                .unwrap_or(0);

            // Extract signature and public key headers
            let sig_b64 = extract_header(&header_str, "x-tsm-policy-signature");
            let pubkey_b64 = extract_header(&header_str, "x-tsm-policy-pubkey");

            // Trim trailing whitespace from the body — json.Marshal never emits
            // a trailing newline, but HTTP transfer may add one.
            let body_trimmed: Vec<u8> = body_bytes
                .iter()
                .rev()
                .skip_while(|&&b| b == b'\n' || b == b'\r' || b == b' ')
                .cloned()
                .collect::<Vec<u8>>()
                .into_iter()
                .rev()
                .collect();

            PollResult::Updated { version, body_bytes: body_trimmed, sig_b64, pubkey_b64 }
        }
        _ => PollResult::Error(format!("unexpected status {status}")),
    }
}

/// Extract a response header value by lowercase name from the header block.
fn extract_header(headers: &str, name: &str) -> Option<String> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with(name) && lower[name.len()..].starts_with(':') {
            return Some(line[name.len() + 1..].trim().to_owned());
        }
    }
    None
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

// ── Crypto helpers ────────────────────────────────────────────────────────────

/// Verify an Ed25519 signature.
///
/// `pub_key_bytes`: raw 32-byte Ed25519 public key.
/// `message`:       the exact byte slice that was signed (canonical JSON body).
/// `sig_b64`:       base64-encoded 64-byte Ed25519 signature from the response header.
fn verify_ed25519(pub_key_bytes: &[u8], message: &[u8], sig_b64: &str) -> Result<(), String> {
    let sig_bytes = base64_decode_simple(sig_b64)
        .map_err(|e| format!("base64 decode signature: {e}"))?;

    let pk = UnparsedPublicKey::new(&signature::ED25519, pub_key_bytes);
    pk.verify(message, &sig_bytes)
        .map_err(|_| "Ed25519 signature mismatch".to_owned())
}

/// Minimal base64 (standard alphabet, with padding) decoder — no external crate.
///
/// ring 0.17 does not re-export base64.  We use a hand-rolled table to avoid
/// pulling in a base64 crate just for this one use-site.
fn base64_decode_simple(s: &str) -> Result<Vec<u8>, String> {
    const TABLE: [u8; 128] = {
        let mut t = [255u8; 128];
        let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0usize;
        while i < alpha.len() {
            t[alpha[i] as usize] = i as u8;
            i += 1;
        }
        t
    };

    let s = s.trim_end_matches('=');
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4 + 1);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in bytes {
        if b > 127 {
            return Err(format!("invalid base64 byte {b}"));
        }
        let v = TABLE[b as usize];
        if v == 255 {
            return Err(format!("invalid base64 char '{}'", b as char));
        }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8 & 0xFF);
        }
    }
    Ok(out)
}
