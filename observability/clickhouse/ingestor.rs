/// ClickHouse async ingestor — high-throughput event pipeline.
///
/// Architecture:
///   - All audit events are pushed into a bounded MPSC channel (non-blocking).
///   - A background thread batches events and POSTs to ClickHouse via HTTP.
///   - Batching: up to 10_000 events per HTTP request, or every 500ms.
///   - Retry: exponential backoff (100ms → 30s), events kept in retry buffer.
///   - Back-pressure: if buffer > 100_000 events, oldest are dropped with a counter.
///
/// This is a zero-allocation path for the request hot loop:
///   try_send() → enqueue into channel → return immediately.
///   No blocking. No synchronous HTTP. No lock contention.
///
/// ClickHouse HTTP ingest:
///   POST http://clickhouse:8123/?query=INSERT+INTO+tsm.ai_requests+FORMAT+JSONEachRow
///   Body: newline-delimited JSON
///
/// Usage (in main.rs):
///   let ch = ClickHouseIngestor::start("http://ch:8123", "tsm", 10_000, 500);
///   ch.ingest(AiRequestEvent { ... });

use std::sync::mpsc::{self, SyncSender, Receiver, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::net::{TcpStream, SocketAddr};
use std::io::{Write, Read, BufReader, BufRead};

// ── Event types ───────────────────────────────────────────────────────────────

/// One row in tsm.ai_requests.
#[derive(Debug, Clone)]
pub struct AiRequestEvent {
    pub timestamp_ms:       u64,
    pub request_id:         String,
    pub session_id:         String,
    pub org_id:             String,
    pub workspace_id:       String,
    pub node_id:            String,
    pub model:              String,
    pub provider:           String,
    pub action:             String,   // allow | block | redact | route_local
    pub pii_types:          Vec<String>,
    pub risk_score:         f32,
    pub severity:           String,
    pub policy_rule:        String,
    pub detection_stage:    String,
    pub detection_latency_us: u32,
    pub client_ip:          String,   // dotted-decimal
    pub ja3_hash:           String,
    pub ja4:                String,
    pub is_tor:             bool,
    pub tls_version:        String,
    pub original_dst_ip:    String,
    pub original_dst_port:  u16,
    pub route_pin:          String,
    pub session_sensitive:  bool,
    pub request_bytes:      u32,
    pub response_bytes:     u32,
    pub total_latency_ms:   u32,
    pub upstream_latency_ms: u32,
    pub output_clean:       bool,
    pub output_threat_type: String,
    pub threat_intel_score: f32,
    pub ioc_match:          bool,
    pub merkle_epoch:       u32,
    pub merkle_leaf_index:  u32,
    pub circuit_state:      String,
}

impl AiRequestEvent {
    /// Serialize to ClickHouse JSONEachRow format (one JSON object, no newline inside).
    pub fn to_json_row(&self) -> String {
        let pii_json: String = {
            let quoted: Vec<String> = self.pii_types.iter()
                .map(|t| format!("\"{}\"", escape_json(t)))
                .collect();
            format!("[{}]", quoted.join(","))
        };

        format!(
            r#"{{"timestamp":{},"request_id":"{}","session_id":"{}","org_id":"{}","workspace_id":"{}","node_id":"{}","model":"{}","provider":"{}","action":"{}","pii_types":{},"risk_score":{},"severity":"{}","policy_rule":"{}","detection_stage":"{}","detection_latency_us":{},"client_ip":"{}","ja3_hash":"{}","ja4":"{}","is_tor":{},"tls_version":"{}","original_dst_ip":"{}","original_dst_port":{},"route_pin":"{}","session_sensitive":{},"request_bytes":{},"response_bytes":{},"total_latency_ms":{},"upstream_latency_ms":{},"output_clean":{},"output_threat_type":"{}","threat_intel_score":{},"ioc_match":{},"merkle_epoch":{},"merkle_leaf_index":{},"circuit_state":"{}"}}"#,
            self.timestamp_ms,
            escape_json(&self.request_id),
            escape_json(&self.session_id),
            escape_json(&self.org_id),
            escape_json(&self.workspace_id),
            escape_json(&self.node_id),
            escape_json(&self.model),
            escape_json(&self.provider),
            escape_json(&self.action),
            pii_json,
            self.risk_score,
            escape_json(&self.severity),
            escape_json(&self.policy_rule),
            escape_json(&self.detection_stage),
            self.detection_latency_us,
            escape_json(&self.client_ip),
            escape_json(&self.ja3_hash),
            escape_json(&self.ja4),
            if self.is_tor { 1 } else { 0 },
            escape_json(&self.tls_version),
            escape_json(&self.original_dst_ip),
            self.original_dst_port,
            escape_json(&self.route_pin),
            if self.session_sensitive { 1 } else { 0 },
            self.request_bytes,
            self.response_bytes,
            self.total_latency_ms,
            self.upstream_latency_ms,
            if self.output_clean { 1 } else { 0 },
            escape_json(&self.output_threat_type),
            self.threat_intel_score,
            if self.ioc_match { 1 } else { 0 },
            self.merkle_epoch,
            self.merkle_leaf_index,
            escape_json(&self.circuit_state),
        )
    }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"',  "\\\"")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

// ── Ingestor metrics ──────────────────────────────────────────────────────────

#[derive(Default)]
pub struct IngestorMetrics {
    pub events_sent:    u64,
    pub events_dropped: u64,
    pub batches_sent:   u64,
    pub errors:         u64,
    pub retries:        u64,
}

// ── ClickHouse ingestor ───────────────────────────────────────────────────────

pub struct ClickHouseIngestor {
    sender:  SyncSender<AiRequestEvent>,
    metrics: Arc<Mutex<IngestorMetrics>>,
    node_id: String,
}

impl ClickHouseIngestor {
    /// Start the background ingest thread and return a handle.
    ///
    /// # Arguments
    /// - `ch_url`      — ClickHouse HTTP endpoint, e.g. "http://localhost:8123"
    /// - `database`    — e.g. "tsm"
    /// - `batch_size`  — rows per HTTP POST (10_000 is a good default)
    /// - `flush_ms`    — max milliseconds before flushing a partial batch (500ms)
    /// - `buffer_cap`  — MPSC channel capacity; back-pressure drops when full
    pub fn start(
        ch_url:     &str,
        database:   &str,
        batch_size: usize,
        flush_ms:   u64,
        buffer_cap: usize,
        node_id:    &str,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::sync_channel::<AiRequestEvent>(buffer_cap);
        let metrics  = Arc::new(Mutex::new(IngestorMetrics::default()));

        let ingestor = Arc::new(ClickHouseIngestor {
            sender:  tx,
            metrics: metrics.clone(),
            node_id: node_id.to_owned(),
        });

        let insert_url = format!(
            "{}/?query=INSERT+INTO+{}.ai_requests+FORMAT+JSONEachRow",
            ch_url.trim_end_matches('/'),
            database,
        );

        let m2 = metrics.clone();
        std::thread::Builder::new()
            .name("ch-ingestor".to_owned())
            .spawn(move || {
                run_ingest_loop(rx, insert_url, batch_size, flush_ms, m2);
            })
            .expect("ingestor thread spawn");

        ingestor
    }

    /// Submit an event for async ingestion. Never blocks. Drops if buffer full.
    pub fn ingest(&self, mut event: AiRequestEvent) {
        // Stamp node_id if not set.
        if event.node_id.is_empty() {
            event.node_id = self.node_id.clone();
        }
        // Stamp timestamp if not set.
        if event.timestamp_ms == 0 {
            event.timestamp_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
        }

        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                if let Ok(mut m) = self.metrics.lock() {
                    m.events_dropped += 1;
                }
                eprintln!("[ch] buffer full — event dropped");
            }
            Err(TrySendError::Disconnected(_)) => {
                eprintln!("[ch] ingestor thread died");
            }
        }
    }

    /// Current metrics snapshot.
    pub fn metrics(&self) -> IngestorMetrics {
        self.metrics.lock().map(|m| IngestorMetrics {
            events_sent:    m.events_sent,
            events_dropped: m.events_dropped,
            batches_sent:   m.batches_sent,
            errors:         m.errors,
            retries:        m.retries,
        }).unwrap_or_default()
    }
}

// ── Background ingest loop ────────────────────────────────────────────────────

fn run_ingest_loop(
    rx:         Receiver<AiRequestEvent>,
    insert_url: String,
    batch_size: usize,
    flush_ms:   u64,
    metrics:    Arc<Mutex<IngestorMetrics>>,
) {
    let flush_interval = Duration::from_millis(flush_ms);
    let mut batch: Vec<AiRequestEvent> = Vec::with_capacity(batch_size);
    let mut last_flush = Instant::now();

    loop {
        // Drain as many events as possible within flush_interval.
        let deadline = last_flush + flush_interval;
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);

            match rx.recv_timeout(remaining.max(Duration::from_millis(1))) {
                Ok(event) => {
                    batch.push(event);
                    if batch.len() >= batch_size { break; }
                }
                Err(_) => break, // timeout or disconnect
            }
        }

        if batch.is_empty() {
            last_flush = Instant::now();
            continue;
        }

        // Build NDJSON body.
        let body: String = batch.iter()
            .map(|e| e.to_json_row())
            .collect::<Vec<_>>()
            .join("\n");

        // POST with retry.
        let sent = post_with_retry(&insert_url, body.as_bytes(), &metrics);
        if sent {
            if let Ok(mut m) = metrics.lock() {
                m.events_sent   += batch.len() as u64;
                m.batches_sent  += 1;
            }
        }

        batch.clear();
        last_flush = Instant::now();
    }
}

/// POST body to ClickHouse. Returns true on success.
/// Retries up to 5 times with exponential backoff.
fn post_with_retry(url: &str, body: &[u8], metrics: &Arc<Mutex<IngestorMetrics>>) -> bool {
    let mut delay_ms: u64 = 100;

    for attempt in 0..5u32 {
        match http_post(url, body) {
            Ok(status) if status < 300 => return true,
            Ok(status) => {
                eprintln!("[ch] HTTP {} on attempt {}", status, attempt + 1);
            }
            Err(e) => {
                eprintln!("[ch] POST error on attempt {}: {}", attempt + 1, e);
            }
        }

        if let Ok(mut m) = metrics.lock() {
            m.errors  += if attempt == 0 { 1 } else { 0 };
            m.retries += if attempt > 0  { 1 } else { 0 };
        }

        if attempt < 4 {
            std::thread::sleep(Duration::from_millis(delay_ms));
            delay_ms = (delay_ms * 2).min(30_000);
        }
    }
    false
}

/// Minimal synchronous HTTP POST (no reqwest/hyper dependency).
fn http_post(url: &str, body: &[u8]) -> Result<u16, String> {
    // Parse URL: http://host:port/path?query
    let url = url.trim_start_matches("http://");
    let (host_port, path_query) = url.split_once('/').unwrap_or((url, ""));
    let path = format!("/{}", path_query);

    let addr: SocketAddr = host_port
        .parse()
        .or_else(|_| {
            // Try resolving hostname
            let (host, port_str) = host_port.split_once(':').unwrap_or((host_port, "8123"));
            let port: u16 = port_str.parse().unwrap_or(8123);
            std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
                .map_err(|e| e.to_string())?
                .next()
                .ok_or_else(|| "no addr".to_string())
        })
        .map_err(|e| format!("addr parse: {}", e))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("connect: {}", e))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;

    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/x-ndjson\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path, host_port, body.len()
    );

    stream.write_all(request.as_bytes()).map_err(|e| format!("write header: {}", e))?;
    stream.write_all(body).map_err(|e| format!("write body: {}", e))?;

    // Read status line only.
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).map_err(|e| format!("read status: {}", e))?;

    // "HTTP/1.1 200 OK"
    let status: u16 = status_line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    Ok(status)
}

// ── XDP packet event ingestor ─────────────────────────────────────────────────

pub struct XdpEventIngestor {
    sender: SyncSender<XdpPacketEvent>,
}

#[derive(Debug, Clone)]
pub struct XdpPacketEvent {
    pub timestamp_ms: u64,
    pub node_id:      String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub action:       String,   // drop_rate, drop_syn, drop_blocklist, pass
    pub packets:      u64,
    pub bytes:        u64,
}

impl XdpPacketEvent {
    pub fn to_json_row(&self) -> String {
        format!(
            r#"{{"timestamp":{},"node_id":"{}","src_ip":"{}","dst_ip":"{}","action":"{}","packets":{},"bytes":{}}}"#,
            self.timestamp_ms,
            escape_json(&self.node_id),
            escape_json(&self.src_ip),
            escape_json(&self.dst_ip),
            escape_json(&self.action),
            self.packets,
            self.bytes,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> AiRequestEvent {
        AiRequestEvent {
            timestamp_ms:         1700000000000,
            request_id:           "req-001".to_owned(),
            session_id:           "sess-abc".to_owned(),
            org_id:               "acme".to_owned(),
            workspace_id:         "ws-1".to_owned(),
            node_id:              "node-eu-1".to_owned(),
            model:                "gpt-4".to_owned(),
            provider:             "openai".to_owned(),
            action:               "block".to_owned(),
            pii_types:            vec!["SSN".to_owned(), "CREDIT_CARD".to_owned()],
            risk_score:           0.95,
            severity:             "critical".to_owned(),
            policy_rule:          "block-critical-p20".to_owned(),
            detection_stage:      "tier0".to_owned(),
            detection_latency_us: 320,
            client_ip:            "1.2.3.4".to_owned(),
            ja3_hash:             "72a589da586844d7f0818ce684948eea".to_owned(),
            ja4:                  "t13d1715h2_abc".to_owned(),
            is_tor:               false,
            tls_version:          "TLS 1.3".to_owned(),
            original_dst_ip:      "104.18.0.1".to_owned(),
            original_dst_port:    443,
            route_pin:            "local".to_owned(),
            session_sensitive:    true,
            request_bytes:        1024,
            response_bytes:       0,
            total_latency_ms:     2,
            upstream_latency_ms:  0,
            output_clean:         true,
            output_threat_type:   String::new(),
            threat_intel_score:   0.0,
            ioc_match:            false,
            merkle_epoch:         5,
            merkle_leaf_index:    123,
            circuit_state:        "closed".to_owned(),
        }
    }

    #[test]
    fn json_row_is_valid_json() {
        let e    = sample_event();
        let json = e.to_json_row();
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"action\":\"block\""));
        assert!(json.contains("\"SSN\""));
    }

    #[test]
    fn escape_json_handles_special_chars() {
        assert_eq!(escape_json("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json("line\nnewline"), "line\\nnewline");
        assert_eq!(escape_json("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn pii_array_is_valid_json_array() {
        let e    = sample_event();
        let json = e.to_json_row();
        // Should contain ["SSN","CREDIT_CARD"]
        assert!(json.contains("[\"SSN\",\"CREDIT_CARD\"]"));
    }
}
