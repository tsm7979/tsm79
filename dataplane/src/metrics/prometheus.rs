use super::{METRICS, MetricsStore};

/// Render all registered metrics in Prometheus text exposition format.
/// No external crate — the format is simple enough to write by hand.
///
/// Format reference: https://prometheus.io/docs/instrumenting/exposition_formats/
pub fn render() -> Vec<u8> {
    let m = &*METRICS;
    let mut out = Vec::with_capacity(4096);

    macro_rules! writeln_buf {
        ($($arg:tt)*) => {
            out.extend_from_slice(format!($($arg)*).as_bytes());
            out.push(b'\n');
        };
    }

    // ── Counters ──────────────────────────────────────────────────────────────
    writeln_buf!("# HELP tsm_requests_total Total requests processed by the data plane");
    writeln_buf!("# TYPE tsm_requests_total counter");
    for (action, count) in m.requests_by_action.iter() {
        writeln_buf!("tsm_requests_total{{action=\"{}\"}} {}", action, count);
    }

    writeln_buf!("# HELP tsm_fastpath_hits_total Requests resolved by the local fast-path scanner");
    writeln_buf!("# TYPE tsm_fastpath_hits_total counter");
    for (pii_type, count) in m.fastpath_hits.iter() {
        if count > 0 {
            writeln_buf!("tsm_fastpath_hits_total{{pii_type=\"{}\"}} {}", pii_type, count);
        }
    }

    writeln_buf!("# HELP tsm_detector_calls_total Requests sent to the Python detector");
    writeln_buf!("# TYPE tsm_detector_calls_total counter");
    writeln_buf!("tsm_detector_calls_total {}", m.detector_calls.get());

    writeln_buf!("# HELP tsm_rate_limited_total Requests rejected by the rate limiter");
    writeln_buf!("# TYPE tsm_rate_limited_total counter");
    writeln_buf!("tsm_rate_limited_total {}", m.rate_limited.get());

    writeln_buf!("# HELP tsm_circuit_open_total Requests rejected because the circuit breaker is open");
    writeln_buf!("# TYPE tsm_circuit_open_total counter");
    for (upstream, count) in m.circuit_open.iter() {
        if count > 0 {
            writeln_buf!("tsm_circuit_open_total{{upstream=\"{}\"}} {}", upstream, count);
        }
    }

    writeln_buf!("# HELP tsm_pii_types_detected_total PII types detected across all requests");
    writeln_buf!("# TYPE tsm_pii_types_detected_total counter");
    for (pii_type, count) in m.pii_types.iter() {
        if count > 0 {
            writeln_buf!("tsm_pii_types_detected_total{{pii_type=\"{}\"}} {}", pii_type, count);
        }
    }

    // ── Histograms ────────────────────────────────────────────────────────────
    writeln_buf!("# HELP tsm_request_duration_ms Request end-to-end latency in milliseconds");
    writeln_buf!("# TYPE tsm_request_duration_ms histogram");
    for (action, hist) in &[
        ("allow",       &m.latency_allow),
        ("block",       &m.latency_block),
        ("redact",      &m.latency_redact),
        ("route_local", &m.latency_route_local),
    ] {
        for (bound, count) in hist.buckets() {
            let le = if bound.is_infinite() { "+Inf".to_owned() } else { format!("{}", bound) };
            writeln_buf!("tsm_request_duration_ms_bucket{{action=\"{}\",le=\"{}\"}} {}", action, le, count);
        }
        writeln_buf!("tsm_request_duration_ms_sum{{action=\"{}\"}} {:.3}", action, hist.sum_ms());
        writeln_buf!("tsm_request_duration_ms_count{{action=\"{}\"}} {}", action, hist.count());
    }

    writeln_buf!("# HELP tsm_detector_duration_ms Detector call latency in milliseconds");
    writeln_buf!("# TYPE tsm_detector_duration_ms histogram");
    for (bound, count) in m.latency_detector.buckets() {
        let le = if bound.is_infinite() { "+Inf".to_owned() } else { format!("{}", bound) };
        writeln_buf!("tsm_detector_duration_ms_bucket{{le=\"{}\"}} {}", le, count);
    }
    writeln_buf!("tsm_detector_duration_ms_sum {:.3}", m.latency_detector.sum_ms());
    writeln_buf!("tsm_detector_duration_ms_count {}", m.latency_detector.count());

    // ── Connections ───────────────────────────────────────────────────────────
    writeln_buf!("# HELP tsm_pool_connections_total TLS connections established to upstreams");
    writeln_buf!("# TYPE tsm_pool_connections_total counter");
    writeln_buf!("tsm_pool_connections_total {}", m.pool_connections.get());

    out
}

/// Returns the same JSON metrics as the TypeScript proxy's snapshot() shape
/// so the existing dashboard works without changes.
pub fn render_json(store: &MetricsStore) -> Vec<u8> {
    let total    = store.requests_by_action.iter().map(|(_, c)| c).sum::<u64>();
    let blocked  = store.requests_by_action.get("block");
    let redacted = store.requests_by_action.get("redact");
    let local    = store.requests_by_action.get("route_local");
    let clean    = store.requests_by_action.get("allow");

    // Top PII types
    let mut top_pii: Vec<serde_json::Value> = store.pii_types
        .iter()
        .filter(|(_, c)| c > 0)
        .map(|(t, c)| serde_json::json!({ "type": t, "count": c }))
        .collect();
    top_pii.sort_by(|a, b| {
        b["count"].as_u64().unwrap_or(0)
            .cmp(&a["count"].as_u64().unwrap_or(0))
    });
    top_pii.truncate(10);

    let out = serde_json::json!({
        "total":        total,
        "blocked":      blocked,
        "redacted":     redacted,
        "routed_local": local,
        "clean":        clean,
        "avg_risk":     store.avg_risk_score(),
        "top_pii":      top_pii,
        "recent":       store.recent_requests(),
        "window_size":  store.ring_size(),
    });
    serde_json::to_vec(&out).unwrap_or_default()
}
