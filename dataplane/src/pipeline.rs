/// Per-request pipeline orchestration.
///
/// Flow:
///   1. Read raw HTTP request bytes from the client socket (with proper body loop)
///   2. Parse HTTP/1.1 or HTTP/2
///   3. Parse AI protocol body (OpenAI or Anthropic)
///   4. Extract user text
///   5. Fast-path detector scan
///      → Clean / Block / Redact / RouteLocal: resolved here
///      → Ambiguous: forward to Python detector (5s timeout, fail-open)
///   6. PolicyEngine::evaluate() to confirm/override the verdict
///   7. AuditLog::append()
///   8. Metrics::record_request()
///   9. Block → return structured 400 JSON error to client
///      Forward → acquire connection from pool → forward → stream response back
///
/// Production fixes applied:
///   Fix 3: Token-bucket rate limiter (per-IP, 429 on excess)
///   Fix 4: Proper body read loop (4 MB limit, 413 / 431 on oversize)
///   Fix 2: SSE streaming loop for chunked/event-stream upstreams
///   Fix 5: Structured block responses with spans and rule name

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json;

use crate::ai::AiRequest;
use crate::audit::AuditLog;
use crate::config::Config;
use crate::detect::{Detector, DetectVerdict, RedactSpan};
use crate::http::{parse_request, ParseResult, build_response};
use crate::http::h1::find_double_crlf;
use crate::metrics::{metrics, RecentRequest};
use crate::policy::{Action, EvalContext, PolicyEngine};
use crate::pool::ConnPool;
use crate::route::{resolve_upstream, resolve_named, build_auth_headers};

use std::collections::HashMap;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum request body size. Bodies larger than this receive 413.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024; // 4 MB

/// Maximum size of request headers. Requests with headers > this receive 431.
const MAX_HEADER_BYTES: usize = 16 * 1024; // 16 KB

// ── Rate limiter ──────────────────────────────────────────────────────────────

/// Token-bucket rate limiter: one bucket per client IP address.
///
/// Each bucket holds up to `burst` tokens. Tokens refill at `rate_per_s`
/// per second. A request consumes one token; if the bucket is empty, the
/// request is rejected with 429.
pub struct RateLimiter {
    /// (tokens, last_refill_instant) per IP
    buckets:    Mutex<HashMap<IpAddr, (f64, Instant)>>,
    rate_per_s: f64,   // requests per second = rpm / 60.0
    burst:      f64,   // maximum burst = rpm (one minute's worth)
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        let rpm = requests_per_minute as f64;
        RateLimiter {
            buckets:    Mutex::new(HashMap::new()),
            rate_per_s: rpm / 60.0,
            burst:      rpm,
        }
    }

    /// Returns `true` if the request is allowed (token consumed), `false` if rate-limited.
    pub fn check_and_consume(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().unwrap();

        // Evict stale entries when the table grows large
        if buckets.len() > 100_000 {
            buckets.retain(|_, (tokens, _)| *tokens < self.burst);
        }

        let now = Instant::now();
        let entry = buckets.entry(ip).or_insert((self.burst, now));
        let (tokens, last) = entry;

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * self.rate_per_s).min(self.burst);
        *last   = now;

        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── Trace header keys ─────────────────────────────────────────────────────────

const TRACE_HEADERS: &[&str] = &[
    "traceparent",
    "tracestate",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
    "x-b3-sampled",
    "x-datadog-trace-id",
    "x-datadog-parent-id",
    "x-datadog-sampling-priority",
    "x-request-id",
];

// ── Request context ───────────────────────────────────────────────────────────

pub struct RequestContext<'a> {
    pub request_id: String,
    pub client_ip:  String,
    pub org_id:     String,
    pub model:      String,
    pub config:     &'a Config,
    pub trace_hdrs: HashMap<String, String>,
}

// ── Main pipeline entry ───────────────────────────────────────────────────────

/// Process one HTTP request from `fd`.
///
/// Returns `true` if the connection should be kept alive, `false` to close.
pub fn handle_connection(
    fd:           RawFd,
    config:       Arc<Config>,
    pool:         Arc<ConnPool>,
    audit:        Arc<AuditLog>,
    policy:       Arc<PolicyEngine>,
    rate_limiter: Arc<RateLimiter>,
) -> bool {
    let mut stream = unsafe { TcpStream::from_raw_fd(fd) };

    // ── Fix 4: Proper body read loop ──────────────────────────────────────────
    let buf = match read_full_request(&mut stream) {
        ReadResult::Ok(b)           => b,
        ReadResult::Closed          => return false,
        ReadResult::HeadersTooLarge => {
            let resp = build_response(431, "Request Header Fields Too Large",
                "text/plain", b"headers exceed 16 KB limit");
            let _ = stream.write_all(&resp);
            return false;
        }
        ReadResult::BodyTooLarge => {
            let resp = build_response(413, "Content Too Large",
                "application/json", b"{\"error\":\"request body exceeds 4 MB limit\"}");
            let _ = stream.write_all(&resp);
            return false;
        }
    };

    let start = Instant::now();

    // Parse HTTP/1.1 request
    let (req, _consumed) = match parse_request(&buf) {
        ParseResult::Complete(req, consumed) => (req, consumed),
        ParseResult::NeedMore => {
            let resp = build_response(400, "Bad Request", "text/plain", b"incomplete request");
            let _ = stream.write_all(&resp);
            return false;
        }
        ParseResult::Error(e) => {
            let msg = format!("parse error: {}", e);
            let resp = build_response(400, "Bad Request", "text/plain", msg.as_bytes());
            let _ = stream.write_all(&resp);
            return false;
        }
    };

    // Extract request metadata
    let request_id = generate_request_id();
    let client_ip  = stream.peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_owned());
    let org_id = req.header(&config.org_header)
        .map(|h| h.value_str().to_owned())
        .unwrap_or_default();

    // ── Fix 3: Rate limiting check ────────────────────────────────────────────
    let ip: IpAddr = client_ip.parse()
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    if !rate_limiter.check_and_consume(ip) {
        metrics().record_rate_limited();
        let resp = build_response(429, "Too Many Requests", "application/json",
            b"{\"error\":\"rate limit exceeded\",\"retry_after\":60}");
        let _ = stream.write_all(&resp);
        // fd stays open for the main loop to close; return false to close connection
        std::mem::forget(stream);
        return false;
    }

    // Extract trace headers
    let mut trace_hdrs: HashMap<String, String> = HashMap::new();
    for &key in TRACE_HEADERS {
        if let Some(h) = req.header(key) {
            trace_hdrs.insert(key.to_owned(), h.value_str().to_owned());
        }
    }

    // Handle /metrics endpoint
    let path = std::str::from_utf8(req.path).unwrap_or("");
    if path == "/metrics" {
        let body = crate::metrics::prometheus::render();
        let resp = build_response(200, "OK", "text/plain; version=0.0.4", &body);
        let _ = stream.write_all(&resp);
        return req.keep_alive();
    }
    if path == "/health" || path == "/healthz" {
        let resp = build_response(200, "OK", "application/json", b"{\"status\":\"ok\"}");
        let _ = stream.write_all(&resp);
        return req.keep_alive();
    }
    if path.starts_with("/api/metrics") {
        let m    = metrics();
        let body = crate::metrics::prometheus::render_json(m);
        let resp = build_response(200, "OK", "application/json", &body);
        let _ = stream.write_all(&resp);
        return req.keep_alive();
    }

    // Parse AI request body
    let ai_req = match AiRequest::from_path_and_body(req.path, req.body) {
        Ok(r)  => r,
        Err(e) => {
            let msg = format!("{{\"error\":\"{}\"}}",  e.replace('"', "'"));
            let resp = build_response(400, "Bad Request", "application/json", msg.as_bytes());
            let _ = stream.write_all(&resp);
            return req.keep_alive();
        }
    };

    let model = ai_req.model().to_owned();
    let text  = ai_req.user_text();

    // ── Fast-path detection ───────────────────────────────────────────────────
    let detector     = Detector::new();
    let fast_verdict = detector.scan(&text);

    // ── Python detector (Ambiguous only) ──────────────────────────────────────
    let verdict = match &fast_verdict {
        DetectVerdict::Ambiguous { .. } => {
            let det_start = Instant::now();
            let py_result = call_python_detector(
                &config.detector_url, &text, &model, &org_id,
                &trace_hdrs, config.detector_timeout_ms,
            );
            metrics().record_detector_call(det_start.elapsed().as_secs_f64() * 1000.0);
            py_result.unwrap_or(fast_verdict)
        }
        other => other.clone(),
    };

    // ── Policy evaluation ─────────────────────────────────────────────────────
    let (pii_types, risk_score, spans) = extract_verdict_metadata(&verdict);
    let severity = crate::detect::Severity::from_risk(risk_score).as_str().to_owned();
    let eval_ctx = EvalContext {
        pii_types:  pii_types.clone(),
        risk_score,
        severity:   severity.clone(),
        model:      model.clone(),
        org_id:     org_id.clone(),
        metadata:   HashMap::new(),
    };
    let policy_result = policy.evaluate(&eval_ctx);

    // ── Final action ──────────────────────────────────────────────────────────
    let final_action = match &policy_result.action {
        Action::Allow         => "allow",
        Action::Block { .. }  => "block",
        Action::Redact        => "redact",
        Action::RouteLocal    => "route_local",
        _                     => "allow",
    };

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    // ── Record fast-path hits in metrics ──────────────────────────────────────
    for pt in &pii_types {
        metrics().record_fastpath_hit(pt);
    }

    // ── Audit log ─────────────────────────────────────────────────────────────
    let _ = audit.append(
        request_id.clone(),
        org_id.clone(),
        model.clone(),
        final_action.to_owned(),
        pii_types.clone(),
        risk_score,
        latency_ms,
        client_ip.clone(),
    );

    // ── Structured access log ─────────────────────────────────────────────────
    crate::telemetry::RequestLog {
        request_id: &request_id,
        method:     req.method,
        path:       req.path,
        status:     if final_action == "block" { 400 } else { 200 },
        action:     final_action,
        pii_types:  &pii_types,
        risk_score,
        latency_ms,
        upstream:   req.path,   // filled in more precisely in forward_request
        client_ip:  &client_ip,
    }.emit();

    // ── Metrics ───────────────────────────────────────────────────────────────
    let recent = RecentRequest {
        request_id: request_id.clone(),
        org_id:     org_id.clone(),
        model:      model.clone(),
        action:     final_action.to_owned(),
        risk_score,
        pii_types:  pii_types.clone(),
        latency_ms,
        timestamp:  unix_now(),
    };
    metrics().record_request(final_action, latency_ms, risk_score, &pii_types, recent);

    // ── Route ─────────────────────────────────────────────────────────────────
    match &policy_result.action {
        Action::Block { reason } => {
            // Fix 5: structured block response with spans and rule name
            let rule_name  = derive_rule_name(&pii_types);
            let span_tuples: Vec<(usize, usize, String)> = spans.iter()
                .map(|s| (s.start, s.end, s.pii_type.clone()))
                .collect();
            let body = ai_req.build_block_response(&pii_types, risk_score, rule_name, &span_tuples);
            let resp = build_response(400, "Bad Request", "application/json", &body);
            let _ = stream.write_all(&resp);
            let keep = req.keep_alive();
            std::mem::forget(stream);
            keep
        }
        Action::Redact => {
            let redacted_text = match &verdict {
                DetectVerdict::Redact { redacted, .. } => redacted.clone(),
                _ => text.clone(),
            };
            let redacted_body = ai_req.redacted_bytes(&redacted_text);
            forward_request(stream, &ai_req, &redacted_body, &model, &trace_hdrs, &config, &pool)
        }
        Action::RouteLocal => {
            let target = resolve_named("ollama").or_else(|| resolve_named("local"));
            if let Some(t) = target {
                forward_to_target(stream, t, req.body, &trace_hdrs, &config, &pool)
            } else {
                forward_request(stream, &ai_req, req.body, &model, &trace_hdrs, &config, &pool)
            }
        }
        _ => {
            // Allow
            forward_request(stream, &ai_req, req.body, &model, &trace_hdrs, &config, &pool)
        }
    }
}

// ── Fix 4: Full request reader ────────────────────────────────────────────────

enum ReadResult {
    Ok(Vec<u8>),
    Closed,
    HeadersTooLarge,
    BodyTooLarge,
}

/// Read a complete HTTP/1.1 request (headers + body) from `stream`.
///
/// Phase 1: Read until `\r\n\r\n` is found — this is the end of headers.
///          Rejects if headers exceed `MAX_HEADER_BYTES`.
/// Phase 2: Parse Content-Length from header bytes.
/// Phase 3: Read exactly Content-Length more body bytes, up to `MAX_BODY_BYTES`.
fn read_full_request(stream: &mut TcpStream) -> ReadResult {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];

    // Phase 1: read until header end (\r\n\r\n)
    let header_end = loop {
        let n = match stream.read(&mut tmp) {
            Ok(0)  => return ReadResult::Closed,
            Err(_) => return ReadResult::Closed,
            Ok(n)  => n,
        };
        buf.extend_from_slice(&tmp[..n]);

        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return ReadResult::HeadersTooLarge;
        }
    };

    // Phase 2: parse Content-Length
    let body_start = header_end + 4;
    let cl = parse_content_length(&buf[..header_end]);

    // Phase 3: read body
    match cl {
        Some(n) if n > MAX_BODY_BYTES => return ReadResult::BodyTooLarge,
        Some(n) => {
            let needed = body_start.saturating_add(n);
            while buf.len() < needed {
                let r = match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(r) => r,
                };
                buf.extend_from_slice(&tmp[..r]);
                if buf.len() > MAX_BODY_BYTES + MAX_HEADER_BYTES {
                    return ReadResult::BodyTooLarge;
                }
            }
            // Truncate to exact request length
            buf.truncate(needed);
        }
        None => {
            // No Content-Length: what we have is all there is
            // (e.g. GET requests, or if the client already sent the full body)
        }
    }

    ReadResult::Ok(buf)
}

/// Parse the `Content-Length` value from a header section (the bytes before `\r\n\r\n`).
fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let headers_str = std::str::from_utf8(headers).ok()?;
    for line in headers_str.split("\r\n") {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            let val = lower["content-length:".len()..].trim();
            return val.parse::<usize>().ok();
        }
    }
    None
}

// ── Upstream forwarding ───────────────────────────────────────────────────────

fn forward_request(
    mut client: TcpStream,
    ai_req:     &AiRequest,
    body:       &[u8],
    model:      &str,
    trace_hdrs: &HashMap<String, String>,
    config:     &Config,
    pool:       &ConnPool,
) -> bool {
    let target = resolve_upstream(model);
    forward_to_target(client, target, body, trace_hdrs, config, pool)
}

fn forward_to_target(
    mut client: TcpStream,
    target:     &'static crate::route::UpstreamTarget,
    body:       &[u8],
    trace_hdrs: &HashMap<String, String>,
    config:     &Config,
    pool:       &ConnPool,
) -> bool {
    // Build the upstream HTTP/1.1 request
    let auth_hdrs = build_auth_headers(target);
    let req_buf   = build_upstream_request(target, body, &auth_hdrs, trace_hdrs);

    // Acquire a pooled connection
    let mut guard = match pool.acquire(target) {
        Ok(g)  => g,
        Err(e) => {
            eprintln!("[pipeline] pool.acquire({}) failed: {}", target.name, e);
            let resp = build_response(502, "Bad Gateway", "application/json",
                b"{\"error\":\"upstream unavailable\"}");
            let _ = client.write_all(&resp);
            return false;
        }
    };

    // Send request to upstream
    let upstream_fd = guard.fd();
    let mut upstream = unsafe { TcpStream::from_raw_fd(upstream_fd) };
    if upstream.write_all(&req_buf).is_err() {
        guard.mark_unhealthy();
        let resp = build_response(502, "Bad Gateway", "application/json",
            b"{\"error\":\"upstream write failed\"}");
        let _ = client.write_all(&resp);
        std::mem::forget(upstream);
        return false;
    }

    // ── Fix 2: Streaming response loop ───────────────────────────────────────
    // Read upstream response headers first to detect SSE / chunked.
    let (header_bytes, is_chunked, is_sse) = match read_upstream_headers(&mut upstream) {
        Some(t) => t,
        None => {
            guard.mark_unhealthy();
            std::mem::forget(upstream);
            return false;
        }
    };

    if is_chunked || is_sse {
        // Streaming: forward in a continuous loop until upstream closes or [DONE]
        let ok = forward_streaming_response(&mut upstream, &mut client, &header_bytes);
        guard.mark_unhealthy(); // streaming connections are not reused
        std::mem::forget(upstream);
        ok
    } else {
        // Non-streaming: headers are the full response (body was read too)
        let _ = client.write_all(&header_bytes);
        std::mem::forget(upstream);
        true
    }
}

/// Read upstream response headers (up to the first `\r\n\r\n`).
///
/// Returns `(header_bytes, is_chunked, is_sse)` or `None` on read error.
/// For non-streaming responses, `header_bytes` includes the body if already
/// buffered within the header read.
fn read_upstream_headers(upstream: &mut TcpStream) -> Option<(Vec<u8>, bool, bool)> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    let header_end = loop {
        let n = match upstream.read(&mut tmp) {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);

        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            // Upstream headers > 64 KB — not valid
            return None;
        }
    };

    let headers_str = std::str::from_utf8(&buf[..header_end]).unwrap_or("").to_lowercase();
    let is_chunked  = headers_str.contains("transfer-encoding: chunked");
    let is_sse      = headers_str.contains("content-type: text/event-stream");

    Some((buf, is_chunked, is_sse))
}

/// Stream an upstream SSE or chunked response to the client in real time.
///
/// Forwards 8 KB at a time, parsing SSE events via `crate::ai::sse::parse_events`.
/// Stops when the upstream closes the connection or a `[DONE]` sentinel is found.
fn forward_streaming_response(
    upstream: &mut TcpStream,
    client:   &mut TcpStream,
    header_bytes: &[u8],
) -> bool {
    use crate::ai::sse::parse_events;

    // Forward headers to client first
    if client.write_all(header_bytes).is_err() {
        return false;
    }

    let mut leftover: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];

    loop {
        let n = match upstream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        leftover.extend_from_slice(&tmp[..n]);

        // Forward raw bytes to client immediately (low latency)
        if client.write_all(&tmp[..n]).is_err() {
            return false;
        }

        // Parse events to detect the [DONE] sentinel
        let (events, consumed) = parse_events(&leftover);
        let done = events.iter().any(|e| e.is_done());
        leftover.drain(..consumed);

        if done || leftover.len() > 1_048_576 {
            break;
        }
    }

    true
}

fn build_upstream_request(
    target:     &crate::route::UpstreamTarget,
    body:       &[u8],
    auth_hdrs:  &[(String, String)],
    trace_hdrs: &HashMap<String, String>,
) -> Vec<u8> {
    let mut req = Vec::with_capacity(512 + body.len());
    req.extend_from_slice(b"POST ");
    req.extend_from_slice(target.base.as_bytes());
    req.extend_from_slice(b"/chat/completions HTTP/1.1\r\nHost: ");
    req.extend_from_slice(target.host.as_bytes());
    req.extend_from_slice(b"\r\nContent-Type: application/json\r\nContent-Length: ");
    req.extend_from_slice(body.len().to_string().as_bytes());
    req.extend_from_slice(b"\r\n");
    for (k, v) in auth_hdrs {
        req.extend_from_slice(k.as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(v.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    for (k, v) in trace_hdrs {
        req.extend_from_slice(k.as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(v.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(body);
    req
}

// ── Python ML detector call ───────────────────────────────────────────────────
//
// Transport selection:
//   1. gRPC (feature = "grpc", GRPC_DETECTOR_URL set) — typed, streaming, efficient
//   2. HTTP/1.1 fallback — raw TCP, no deps, always available
//
// The Python detector runs ML layers Rust cannot: Isolation Forest, sentence-
// transformer semantic embeddings, spaCy NER, LLM-assisted classification.
// Rust has already run regex + entropy + structural on the fast path.

fn call_python_detector(
    url:        &str,
    text:       &str,
    model:      &str,
    org_id:     &str,
    trace_hdrs: &HashMap<String, String>,
    timeout_ms: u64,
) -> Option<DetectVerdict> {
    // ── gRPC path (when feature enabled + GRPC_DETECTOR_URL set) ──────────────
    #[cfg(feature = "grpc")]
    if let Ok(grpc_url) = std::env::var("GRPC_DETECTOR_URL") {
        return call_detector_grpc(&grpc_url, text, model, org_id, timeout_ms);
    }

    // ── HTTP/1.1 fallback ─────────────────────────────────────────────────────
    call_detector_http(url, text, model, org_id, trace_hdrs, timeout_ms)
}

/// gRPC call via tonic (only compiled when `grpc` feature is active).
#[cfg(feature = "grpc")]
fn call_detector_grpc(
    grpc_url:   &str,
    text:       &str,
    model:      &str,
    org_id:     &str,
    timeout_ms: u64,
) -> Option<DetectVerdict> {
    // tonic is async; we block here since pipeline threads are synchronous OS threads.
    // A dedicated tokio runtime is constructed once per thread (lazy static pattern).
    use std::cell::RefCell;

    thread_local! {
        static RT: RefCell<Option<tokio::runtime::Runtime>> = RefCell::new(None);
    }

    RT.with(|rt_cell| {
        let mut rt_ref = rt_cell.borrow_mut();
        if rt_ref.is_none() {
            *rt_ref = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok();
        }
        let rt = rt_ref.as_ref()?;

        rt.block_on(async move {
            use crate::gen::tsm_detect::detect_service_client::DetectServiceClient;
            use crate::gen::tsm_detect::DetectRequest;

            let mut client = DetectServiceClient::connect(grpc_url.to_owned())
                .await
                .ok()?;

            let request = tonic::Request::new(DetectRequest {
                model:      model.to_owned(),
                messages:   vec![crate::gen::tsm_detect::Message {
                    role:    "user".to_owned(),
                    content: text.to_owned(),
                }],
                prompt:     text.to_owned(),
                org_id:     org_id.to_owned(),
                request_id: String::new(),
                metadata:   std::collections::HashMap::new(),
            });

            let response = client.detect(request).await.ok()?.into_inner();

            let action_str = match response.action {
                1 => "redact",
                2 => "block",
                3 => "route_local",
                _ => "allow",
            };
            parse_detector_response(action_str, response.risk_score as f64, response.pii_types, response.severity, text)
        })
    })
}

/// HTTP/1.1 fallback: raw TCP, JSON body — no external crate dependencies.
fn call_detector_http(
    url:        &str,
    text:       &str,
    model:      &str,
    org_id:     &str,
    trace_hdrs: &HashMap<String, String>,
    timeout_ms: u64,
) -> Option<DetectVerdict> {
    use std::net::TcpStream;

    let without_scheme = url.trim_start_matches("http://").trim_start_matches("https://");
    let (host_port, _) = without_scheme.split_once('/').unwrap_or((without_scheme, "detect"));

    let mut stream = TcpStream::connect(host_port).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();

    let body = serde_json::json!({
        "model":    model,
        "messages": [{ "role": "user", "content": text }],
        "prompt":   text,
        "metadata": { "org_id": org_id }
    }).to_string();

    let mut req = Vec::new();
    req.extend_from_slice(b"POST /detect HTTP/1.1\r\nHost: ");
    req.extend_from_slice(host_port.as_bytes());
    req.extend_from_slice(b"\r\nContent-Type: application/json\r\nContent-Length: ");
    req.extend_from_slice(body.len().to_string().as_bytes());
    req.extend_from_slice(b"\r\n");
    for (k, v) in trace_hdrs {
        req.extend_from_slice(k.as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(v.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(body.as_bytes());
    stream.write_all(&req).ok()?;

    let mut resp_buf = vec![0u8; 16384];
    let n = stream.read(&mut resp_buf).ok()?;
    let resp_str = std::str::from_utf8(&resp_buf[..n]).ok()?;

    let body_start = resp_str.find("\r\n\r\n")? + 4;
    let v: serde_json::Value = serde_json::from_str(&resp_str[body_start..]).ok()?;

    let action    = v["action"].as_str().unwrap_or("allow");
    let risk      = v["risk_score"].as_f64().unwrap_or(0.0);
    let pii_types: Vec<String> = v["pii_types"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(str::to_owned).collect())
        .unwrap_or_default();
    let severity  = v["severity"].as_str().unwrap_or("none").to_owned();
    parse_detector_response(action, risk, pii_types, severity, text)
}

/// Map action string + metadata into a DetectVerdict.
fn parse_detector_response(
    action:    &str,
    risk:      f64,
    pii_types: Vec<String>,
    severity:  String,
    orig_text: &str,
) -> Option<DetectVerdict> {
    Some(match action {
        "block"       => DetectVerdict::Block { pii_types, risk_score: risk, severity, spans: vec![] },
        "redact"      => DetectVerdict::Redact { pii_types, risk_score: risk, redacted: orig_text.to_owned() },
        "route_local" => DetectVerdict::RouteLocal { pii_types, risk_score: risk },
        _             => DetectVerdict::Clean,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract (pii_types, risk_score, spans) from a verdict.
fn extract_verdict_metadata(verdict: &DetectVerdict) -> (Vec<String>, f64, Vec<RedactSpan>) {
    match verdict {
        DetectVerdict::Clean                                         => (vec![], 0.0, vec![]),
        DetectVerdict::Block { pii_types, risk_score, spans, .. }   => (pii_types.clone(), *risk_score, spans.clone()),
        DetectVerdict::Redact { pii_types, risk_score, .. }         => (pii_types.clone(), *risk_score, vec![]),
        DetectVerdict::RouteLocal { pii_types, risk_score }         => (pii_types.clone(), *risk_score, vec![]),
        DetectVerdict::Ambiguous { risk_score, .. }                  => (vec![], *risk_score, vec![]),
    }
}

/// Derive a rule name from detected PII types for use in structured block responses.
fn derive_rule_name(pii_types: &[String]) -> &'static str {
    if pii_types.iter().any(|t| t == "JAILBREAK") {
        "block-jailbreak-p30"
    } else if pii_types.iter().any(|t| {
        t.ends_with("_KEY") || t.ends_with("_TOKEN") || t == "PRIVATE_KEY"
    }) {
        "block-critical-secrets-p20"
    } else if pii_types.iter().any(|t| t == "SSN" || t == "CREDIT_CARD") {
        "block-critical-pii-p10"
    } else {
        "block-sensitive-data-p50"
    }
}

fn generate_request_id() -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tid = std::thread::current().id();
    format!("tsm-{:x}-{:?}", ts & 0xffff_ffff_ffff, tid)
        .replace("ThreadId(", "")
        .replace(')', "")
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
