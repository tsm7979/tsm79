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
use crate::audit::{AuditLog, AuditSink, AuditEvent};
use crate::config::Config;
use crate::detect::{Detector, DetectVerdict, RedactSpan};
use crate::http::{parse_request, ParseResult, build_response};
use crate::http::h1::find_double_crlf;
use crate::metrics::{metrics, RecentRequest};
use crate::policy::{Action, EvalContext, PolicyEngine};
use crate::pool::ConnPool;
use crate::route::{resolve_upstream, resolve_named, build_auth_headers, SessionRouter, RoutePin, extract_session_id};
use crate::tproxy::ConnContext;

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
    fd:                RawFd,
    config:            Arc<Config>,
    pool:              Arc<ConnPool>,
    audit:             Arc<AuditLog>,
    policy:            Arc<PolicyEngine>,
    rate_limiter:      Arc<RateLimiter>,
    pg_sink:           Option<Arc<AuditSink>>,
    distributed_state: Arc<dyn crate::store::DistributedState>,
    session_router:    Arc<SessionRouter>,
    merkle_chain:      Arc<std::sync::Mutex<crate::audit::MerkleAuditChain>>,
    ch_ingestor:       Option<Arc<crate::ingest::ClickHouseIngestor>>,
    conn_ctx:          ConnContext,
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

    // ── JA3/JA4 fingerprinting ─────────────────────────────────────────────────
    // Probe the raw bytes for a TLS ClientHello record (content type 0x16).
    // This fires on the *first* request of a connection — when a client opens
    // a raw TLS socket directly to TSM rather than sending plaintext HTTP.
    // On subsequent keep-alive iterations the bytes are HTTP, so the probe
    // quietly produces None and we fall back to conn_ctx fields (which may have
    // been pre-populated by a TLS acceptor layer above us).
    let (conn_ja3_hash, conn_ja4): (String, String) = {
        let from_buf = if buf.first() == Some(&0x16) {
            crate::tls::Ja3Fingerprint::from_record(&buf).ok()
        } else {
            None
        };
        if let Some(ref fp) = from_buf {
            if fp.is_malicious() {
                crate::log_warn!("pipeline", "malicious TLS fingerprint — connection will be tracked";
                    "ja3"    => fp.ja3_hash.as_str(),
                    "ja4"    => fp.ja4.as_str(),
                    "threat" => fp.lookup_threat()
                                   .map(|t| t.tool)
                                   .unwrap_or("unknown")
                );
            }
            (fp.ja3_hash.clone(), fp.ja4.clone())
        } else {
            // Fall back to values pre-populated by a TLS acceptor layer (e.g., the
            // MITM ServerHandshake path or an upstream TLS terminator that injects
            // the fingerprint via ConnContext before calling handle_connection).
            (
                conn_ctx.ja3_hash.clone().unwrap_or_default(),
                conn_ctx.ja4.clone().unwrap_or_default(),
            )
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
        let body = format!(
            r#"{{"status":"ok","circuits":{{"openai":"{}","anthropic":"{}"}}}}"#,
            pool.circuit_state("openai"),
            pool.circuit_state("anthropic"),
        );
        let resp = build_response(200, "OK", "application/json", body.as_bytes());
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

    // Extract the W3C traceparent header (or synthesise one) for span correlation
    let traceparent = trace_hdrs.get("traceparent")
        .cloned()
        .unwrap_or_else(|| format!("00-{}-{}-01", &request_id, &request_id[..16]));

    // ── Stage: Classify (fast-path detector) ──────────────────────────────────
    let fast_verdict = {
        let _span = crate::telemetry::PipelineSpan::start(
            crate::telemetry::Stage::Classify, &request_id, &traceparent);
        let detector = Detector::new();
        detector.scan(&text)
    };

    // ── Stage: ONNX INT8 (Ambiguous triage — <1 ms, no Python round-trip) ────────
    // When the fast Rust detector returns Ambiguous, run the INT8 ONNX security
    // classifier first. If it is confident (≥0.85) we resolve immediately.
    // Only unconfident or escalation-worthy verdicts reach the Python service.
    let verdict = match &fast_verdict {
        DetectVerdict::Ambiguous { risk_score: fast_risk, .. } => {
            let onnx_start = Instant::now();
            let onnx = crate::detect::onnx_engine::classify(&text);
            let onnx_us = onnx_start.elapsed().as_micros() as u64;

            if onnx.is_actionable() {
                // ONNX is confident — convert to DetectVerdict without Python
                use crate::detect::onnx_engine::SecurityLabel;
                match onnx.label {
                    SecurityLabel::Clean => {
                        log_debug!("pipeline", "ONNX resolved Ambiguous → Clean";
                            "confidence" => onnx.confidence,
                            "latency_us" => onnx_us
                        );
                        DetectVerdict::Clean
                    }
                    SecurityLabel::Jailbreak => DetectVerdict::Block {
                        pii_types:  vec!["JAILBREAK".to_owned()],
                        risk_score: (onnx.risk_score as f64 * 100.0).min(100.0),
                        severity:   "critical".to_owned(),
                        spans:      vec![],
                    },
                    SecurityLabel::PiiLeak => DetectVerdict::Ambiguous {
                        risk_score: (onnx.risk_score as f64 * 100.0).max(*fast_risk),
                        reason:     crate::detect::AmbiguousReason::NerKeywords,
                    },
                    SecurityLabel::SecretExposure => DetectVerdict::Block {
                        pii_types:  vec!["ENCODED_SECRET".to_owned()],
                        risk_score: (onnx.risk_score as f64 * 100.0).min(100.0),
                        severity:   "critical".to_owned(),
                        spans:      vec![],
                    },
                }
            } else if onnx.needs_escalation() {
                // ONNX uncertain — escalate to Python
                let _span = crate::telemetry::PipelineSpan::start(
                    crate::telemetry::Stage::PyDetector, &request_id, &traceparent);
                let det_start = Instant::now();
                let py_result = call_python_detector(
                    &config.detector_url, &text, &model, &org_id,
                    &trace_hdrs, config.detector_timeout_ms,
                );
                metrics().record_detector_call(det_start.elapsed().as_secs_f64() * 1000.0);
                py_result.unwrap_or_else(|| fast_verdict.clone())
            } else {
                // ONNX says low risk, no escalation needed
                DetectVerdict::Clean
            }
        }
        other => other.clone(),
    };

    // ── Stage: Policy ─────────────────────────────────────────────────────────
    let (pii_types, risk_score, spans) = {
        let _span = crate::telemetry::PipelineSpan::start(
            crate::telemetry::Stage::Policy, &request_id, &traceparent);

        let meta = extract_verdict_metadata(&verdict);
        meta
    };
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

    // ── Session-pinned deterministic routing (Gap 9 fix) ─────────────────────
    // Extract session ID from request headers/body for conversation continuity.
    // Once a session is pinned to local (due to sensitive content), it stays
    // local for ALL subsequent turns — prevents context fragmentation.
    let session_id = {
        let all_headers: Vec<(Vec<u8>, Vec<u8>)> = req.headers.iter()
            .map(|h| (h.name.to_vec(), h.value.to_vec()))
            .collect();
        let auth_token = req.header("authorization")
            .map(|h| h.value_str())
            .unwrap_or("");
        extract_session_id(&all_headers, req.body, auth_token, req.path)
    };

    let is_sensitive = matches!(&policy_result.action, Action::Block { .. } | Action::RouteLocal);

    // ── Session pinning via distributed state (Redis if available) ────────────
    // Use distributed_state for cross-node session consistency. The in-memory
    // session_router is kept as the in-process authoritative view for this node;
    // distributed_state synchronises across the cluster.
    let session_pin = {
        let dist_pin = distributed_state.session_pin(&session_id, is_sensitive);
        // Also record in the local session router so this node's in-memory view
        // stays consistent (avoids a second Redis round-trip on keep-alive).
        session_router.route(&session_id, is_sensitive);
        dist_pin
    };

    // Override policy action to RouteLocal if session is pinned local
    let policy_result = if session_pin == RoutePin::Local
        && matches!(&policy_result.action, Action::Allow)
    {
        // Session was previously flagged — force local routing for continuity
        crate::policy::PolicyResult {
            action:    Action::RouteLocal,
            rule_name: "session-pinned-local".to_owned(),
        }
    } else {
        policy_result
    };

    // ── Merkle audit chain entry ──────────────────────────────────────────────
    // Append every request to the tamper-evident Merkle chain.
    // This runs after policy evaluation so the action is known.
    {
        let action_str = match &policy_result.action {
            Action::Allow      => "allow",
            Action::Block { .. }=> "block",
            Action::Redact     => "redact",
            Action::RouteLocal => "route_local",
            _                  => "allow",
        };
        if let Ok(mut chain) = merkle_chain.lock() {
            chain.push(&session_id, action_str);
        }
    }

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

    // ── Audit log (JSONL chain) ───────────────────────────────────────────────
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

    // ── Audit sink (PostgreSQL + Kafka) ───────────────────────────────────────
    if let Some(ref sink) = pg_sink {
        let redact_spans_json = {
            let arr: Vec<_> = spans.iter()
                .map(|s| format!("{{\"start\":{},\"end\":{},\"type\":{:?}}}", s.start, s.end, s.pii_type))
                .collect();
            format!("[{}]", arr.join(","))
        };
        let method_str = std::str::from_utf8(req.method).unwrap_or("POST");
        let path_str   = std::str::from_utf8(req.path).unwrap_or("/");
        let upstream_target = resolve_upstream(&model);
        let upstream_key = upstream_target.name;

        // Derive prev_hash from the JSONL audit chain (last known hash)
        let (prev_h, entry_h) = audit.last_hashes();
        let event = AuditEvent {
            org_id:            config.org_id.clone(),
            workspace_id:      config.workspace_id.clone(),
            request_id:        request_id.clone(),
            node_id:           config.node_id.clone(),
            client_ip:         client_ip.clone(),
            method:            method_str.to_owned(),
            path:              path_str.to_owned(),
            model:             model.clone(),
            upstream:          upstream_key.to_string(),
            action:            final_action.to_owned(),
            rule_fired:        policy_result.rule_name.clone(),
            pii_types:         pii_types.clone(),
            risk_score,
            severity:          severity.clone(),
            streamed:          false,
            redacted:          final_action == "redact",
            redact_spans_json,
            latency_ms,
            detector_ms:       0.0,
            upstream_ms:       0.0,
            prompt_tokens:     0,
            completion_tokens: 0,
            prev_hash:         prev_h,
            entry_hash:        entry_h,
            traceparent:       traceparent.clone(),
            tags_json:         "{}".to_owned(),
            spans_json:        "[]".to_owned(),
        };
        sink.submit(event);
    }

    // ── ClickHouse ingest (non-blocking, fire-and-forget) ─────────────────────
    // Pushes one row into the bounded MPSC channel. The background thread
    // batches and POSTs to ClickHouse. try_send() never blocks the hot path.
    if let Some(ref ch) = ch_ingestor {
        let (merkle_epoch, merkle_leaf) = {
            merkle_chain.lock()
                .map(|c| (c.current_epoch() as u32, c.current_leaf() as u32))
                .unwrap_or((0, 0))
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let event = crate::ingest::AiRequestEvent {
            timestamp_ms:        now_ms,
            request_id:          request_id.clone(),
            session_id:          session_id.clone(),
            org_id:              org_id.clone(),
            workspace_id:        config.workspace_id.clone(),
            node_id:             config.node_id.clone(),
            model:               model.clone(),
            provider:            infer_provider(&model),
            action:              final_action.to_owned(),
            pii_types:           pii_types.clone(),
            risk_score:          risk_score as f32,
            severity:            severity.clone(),
            policy_rule:         policy_result.rule_name.clone(),
            detection_stage:     infer_detection_stage(&fast_verdict),
            detection_latency_us: (latency_ms * 1000.0) as u32,
            client_ip:           client_ip.clone(),
            ja3_hash:            conn_ja3_hash,
            ja4:                 conn_ja4,
            is_tor:              false,
            tls_version:         String::new(),
            original_dst_ip:     conn_ctx.original_dst
                                    .map(|a| a.ip().to_string())
                                    .unwrap_or_default(),
            original_dst_port:   conn_ctx.original_dst
                                    .map(|a| a.port())
                                    .unwrap_or(0),
            route_pin:           format!("{:?}", session_pin).to_lowercase(),
            session_sensitive:   is_sensitive,
            request_bytes:       buf.len() as u32,
            response_bytes:      0,               // filled by forward path
            total_latency_ms:    latency_ms as u32,
            upstream_latency_ms: 0,               // filled by forward path
            output_clean:        true,
            output_threat_type:  String::new(),
            threat_intel_score:  0.0,
            ioc_match:           false,
            merkle_epoch,
            merkle_leaf_index:   merkle_leaf,
            circuit_state:       pool.circuit_state(upstream_target.name).to_owned(),
        };
        ch.ingest(event);
    }

    // ── Stage: Respond — emit structured access log ───────────────────────────
    let _respond_span = crate::telemetry::PipelineSpan::start(
        crate::telemetry::Stage::Respond, &request_id, &traceparent);

    crate::telemetry::RequestLog {
        request_id:  &request_id,
        method:      req.method,
        path:        req.path,
        status:      if final_action == "block" { 400 } else { 200 },
        action:      final_action,
        rule_fired:  &policy_result.rule_name,
        pii_types:   &pii_types,
        risk_score,
        latency_ms,
        upstream:    req.path,
        client_ip:   &client_ip,
        traceparent: &traceparent,
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
            forward_request(stream, &ai_req, &redacted_body, &model, &trace_hdrs, &config, &pool,
                            &request_id, final_action)
        }
        Action::RouteLocal => {
            let target = resolve_named("ollama").or_else(|| resolve_named("local"));
            if let Some(t) = target {
                forward_to_target(stream, t, req.body, &trace_hdrs, &config, &pool,
                                  &request_id, final_action)
            } else {
                forward_request(stream, &ai_req, req.body, &model, &trace_hdrs, &config, &pool,
                                &request_id, final_action)
            }
        }
        _ => {
            // Allow
            forward_request(stream, &ai_req, req.body, &model, &trace_hdrs, &config, &pool,
                            &request_id, final_action)
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
    mut client:  TcpStream,
    ai_req:      &AiRequest,
    body:        &[u8],
    model:       &str,
    trace_hdrs:  &HashMap<String, String>,
    config:      &Config,
    pool:        &ConnPool,
    request_id:  &str,
    action:      &str,
) -> bool {
    let target = resolve_upstream(model);
    forward_to_target(client, target, body, trace_hdrs, config, pool, request_id, action)
}

fn forward_to_target(
    mut client:  TcpStream,
    target:      &'static crate::route::UpstreamTarget,
    body:        &[u8],
    trace_hdrs:  &HashMap<String, String>,
    config:      &Config,
    pool:        &ConnPool,
    request_id:  &str,
    action:      &str,
) -> bool {
    // Build the upstream HTTP/1.1 request (include X-TSM-Trace-ID for upstream observability)
    let auth_hdrs = build_auth_headers(target);
    let req_buf   = build_upstream_request(target, body, &auth_hdrs, trace_hdrs, request_id);

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

    // Inject TSM tracing headers into the upstream response before forwarding to client
    let tagged_headers = inject_tsm_response_headers(&header_bytes, request_id, action);

    if is_chunked || is_sse {
        // Streaming: forward in a continuous loop until upstream closes or [DONE]
        let upstream_kind = if target.name == "anthropic" {
            crate::ai::sse::UpstreamKind::Anthropic
        } else {
            crate::ai::sse::UpstreamKind::OpenAI
        };
        let ok = forward_streaming_response(&mut upstream, &mut client, &tagged_headers, upstream_kind);
        guard.mark_unhealthy(); // streaming connections are not reused
        std::mem::forget(upstream);
        ok
    } else {
        // Non-streaming: headers are the full response (body was read too)
        let _ = client.write_all(&tagged_headers);
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

/// Stream an upstream SSE or chunked response to the client.
///
/// Uses `SseRedactBuffer` to detect and redact PII in the token stream.
/// Events safely past the 200-char lookahead window are forwarded immediately;
/// the tail is scanned and potentially redacted when [DONE] arrives.
fn forward_streaming_response(
    upstream:     &mut TcpStream,
    client:       &mut TcpStream,
    header_bytes: &[u8],
    kind:         crate::ai::sse::UpstreamKind,
) -> bool {
    use crate::ai::sse::{parse_events, SseRedactBuffer};

    // Forward (already-tagged) headers to client first
    if client.write_all(header_bytes).is_err() {
        return false;
    }

    let mut buf   = SseRedactBuffer::new();
    let mut raw   = Vec::<u8>::new();
    let mut tmp   = [0u8; 8192];

    loop {
        let n = match upstream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        raw.extend_from_slice(&tmp[..n]);

        // Parse complete SSE events out of the buffer
        let (events, consumed) = parse_events(&raw);
        raw.drain(..consumed);

        let mut done = false;
        for ev in events {
            if ev.is_done() {
                // Flush the lookahead tail (with redaction if needed) then send [DONE]
                for safe_ev in buf.flush_done() {
                    if client.write_all(&safe_ev.encode()).is_err() { return false; }
                }
                if client.write_all(&ev.encode()).is_err() { return false; }
                done = true;
                break;
            }

            // Push to redact buffer; forward immediately-safe events
            for safe_ev in buf.push(ev, kind) {
                if client.write_all(&safe_ev.encode()).is_err() { return false; }
            }
        }

        if done || raw.len() > 1_048_576 {
            break;
        }
    }

    true
}

// ── TSM response header injection ─────────────────────────────────────────────

/// Inject `X-TSM-Trace-ID` and `X-TSM-Action-Taken` into an upstream HTTP
/// response buffer before forwarding it to the client.
///
/// Finds the `\r\n\r\n` header terminator and inserts the two headers just
/// before it, so the client always sees which request ID was assigned and what
/// action TSM took (allow / redact / block / route_local).
fn inject_tsm_response_headers(headers: &[u8], request_id: &str, action: &str) -> Vec<u8> {
    use crate::http::h1::find_double_crlf;
    if let Some(end) = find_double_crlf(headers) {
        let mut out = Vec::with_capacity(headers.len() + 128);
        // Everything up to (and including) the last header line's \r\n
        out.extend_from_slice(&headers[..end + 2]);
        // Inject TSM tracing headers
        out.extend_from_slice(b"X-TSM-Trace-ID: ");
        out.extend_from_slice(request_id.as_bytes());
        out.extend_from_slice(b"\r\nX-TSM-Action-Taken: ");
        out.extend_from_slice(action.as_bytes());
        out.extend_from_slice(b"\r\n");
        // Blank line that terminates headers
        out.extend_from_slice(b"\r\n");
        // Any body bytes already buffered alongside headers
        out.extend_from_slice(&headers[end + 4..]);
        out
    } else {
        // Malformed response: pass through as-is
        headers.to_vec()
    }
}

fn build_upstream_request(
    target:     &crate::route::UpstreamTarget,
    body:       &[u8],
    auth_hdrs:  &[(String, String)],
    trace_hdrs: &HashMap<String, String>,
    request_id: &str,
) -> Vec<u8> {
    let mut req = Vec::with_capacity(512 + body.len());
    req.extend_from_slice(b"POST ");
    req.extend_from_slice(target.base.as_bytes());
    req.extend_from_slice(b"/chat/completions HTTP/1.1\r\nHost: ");
    req.extend_from_slice(target.host.as_bytes());
    req.extend_from_slice(b"\r\nContent-Type: application/json\r\nContent-Length: ");
    req.extend_from_slice(body.len().to_string().as_bytes());
    req.extend_from_slice(b"\r\n");
    // Propagate TSM trace ID to upstream for end-to-end traceability
    req.extend_from_slice(b"X-TSM-Trace-ID: ");
    req.extend_from_slice(request_id.as_bytes());
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

/// Map a model name to its AI provider label for ClickHouse.
fn infer_provider(model: &str) -> String {
    if model.starts_with("gpt") || model.starts_with("o1") || model.starts_with("o3") {
        "openai"
    } else if model.starts_with("claude") {
        "anthropic"
    } else if model.starts_with("gemini") || model.starts_with("palm") {
        "google"
    } else if model.starts_with("mistral") || model.starts_with("mixtral") {
        "mistral"
    } else if model.starts_with("command") {
        "cohere"
    } else if model.contains("llama") || model.contains("ollama") {
        "local"
    } else {
        "unknown"
    }
    .to_owned()
}

/// Which detection stage resolved the verdict (for ClickHouse observability).
fn infer_detection_stage(verdict: &DetectVerdict) -> String {
    match verdict {
        DetectVerdict::Clean                  => "prefilter",
        DetectVerdict::Block { pii_types, .. } => {
            if pii_types.iter().any(|t| t.starts_with("BPE:")) {
                "bpe"
            } else if pii_types.iter().any(|t| t == "JAILBREAK") {
                "regex"
            } else {
                "regex"
            }
        }
        DetectVerdict::Redact { .. }          => "regex",
        DetectVerdict::RouteLocal { .. }      => "regex",
        DetectVerdict::Ambiguous { .. }       => "tier1",
    }
    .to_owned()
}
