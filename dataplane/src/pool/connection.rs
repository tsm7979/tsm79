/// Persistent TLS connection pool — 8 connections per upstream.
///
/// On `acquire()`:
///   1. Pop an idle `PooledConn` from the pool for this upstream.
///   2. If the connection has expired or the pool is empty, open a new TCP+TLS connection.
/// On `ConnGuard::drop()`:
///   - If the connection is healthy, push it back into the idle pool.
///   - Otherwise, close the fd.
///
/// Connection health: a connection is considered healthy if its idle time
/// hasn't exceeded `MAX_IDLE_SECS` and no socket error is set.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::pool::circuit::{CircuitBreaker, CircuitDecision, Outcome};
use crate::route::UpstreamTarget;
use crate::tls::AppKeys;
use crate::tls::keys::CipherSuite;
use crate::tls::record::{ContentType, RecordLayer};
use crate::tls::handshake::ClientHandshake;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Maximum time a connection may sit idle before being discarded.
const MAX_IDLE_SECS: u64 = 30;

// ── Pooled connection ─────────────────────────────────────────────────────────

/// A live connection to an upstream — TCP socket + TLS application keys.
pub struct PooledConn {
    pub fd:       RawFd,
    pub app_keys: AppKeys,
    pub upstream: &'static str,
    expiry:       Instant,
    pub h2:       bool,    // true if upstream negotiated HTTP/2 via ALPN
}

impl PooledConn {
    pub fn new(fd: RawFd, app_keys: AppKeys, upstream: &'static str, h2: bool) -> Self {
        PooledConn {
            fd,
            app_keys,
            upstream,
            expiry: Instant::now() + Duration::from_secs(MAX_IDLE_SECS),
            h2,
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expiry
    }

    /// Refresh the expiry timer (call when the connection is returned to the pool).
    pub fn refresh(&mut self) {
        self.expiry = Instant::now() + Duration::from_secs(MAX_IDLE_SECS);
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        // Close the fd when the connection is discarded
        unsafe { libc::close(self.fd); }
    }
}

// ── Connection guard ──────────────────────────────────────────────────────────

/// A checked-out connection.  When dropped, returns to the pool if healthy.
pub struct ConnGuard {
    inner:    Option<PooledConn>,
    pool:     *const ConnPool,
    healthy:  bool,
}

impl ConnGuard {
    /// Mark this connection as unhealthy so it won't be returned to the pool.
    pub fn mark_unhealthy(&mut self) {
        self.healthy = false;
    }

    pub fn fd(&self) -> RawFd {
        self.inner.as_ref().map(|c| c.fd).unwrap_or(-1)
    }

    pub fn is_h2(&self) -> bool {
        self.inner.as_ref().map(|c| c.h2).unwrap_or(false)
    }

    /// Application traffic keys for this connection (None only if inner is gone).
    pub fn app_keys(&self) -> Option<&AppKeys> {
        self.inner.as_ref().map(|c| &c.app_keys)
    }

    /// Returns true if this connection has real TLS keys (non-zero key material).
    pub fn has_tls(&self) -> bool {
        self.inner.as_ref().map(|c| c.app_keys.client.key.iter().any(|&b| b != 0)).unwrap_or(false)
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if !self.healthy {
            // Record the failure in the circuit breaker before discarding.
            if let Some(ref conn) = self.inner {
                // SAFETY: pool pointer is valid for the lifetime of this guard
                unsafe {
                    (*self.pool).circuits.lock().unwrap()
                        .get(conn.upstream)
                        .map(|cb| cb.record(Outcome::Failure));
                }
            }
            return; // PooledConn::drop() will close the fd
        }
        if let Some(mut conn) = self.inner.take() {
            conn.refresh();
            // Return to pool
            // SAFETY: pool pointer is valid for the lifetime of this guard
            unsafe { (*self.pool).return_conn(conn); }
        }
    }
}

// ── Connection pool ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PoolError {
    ConnectFailed(std::io::Error),
    TlsFailed(&'static str),
    NoHealthySlot,
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::ConnectFailed(e) => write!(f, "TCP connect failed: {}", e),
            PoolError::TlsFailed(s)     => write!(f, "TLS handshake failed: {}", s),
            PoolError::NoHealthySlot    => write!(f, "no healthy upstream slot"),
        }
    }
}

pub struct ConnPool {
    /// Map from upstream name → idle connections (LIFO stack)
    pools:    Mutex<HashMap<&'static str, Vec<PooledConn>>>,
    max_idle: usize,
    /// Per-upstream circuit breakers (created on first use)
    circuits: Mutex<HashMap<&'static str, CircuitBreaker>>,
}

impl ConnPool {
    pub fn new(max_idle: usize) -> Self {
        ConnPool {
            pools:    Mutex::new(HashMap::new()),
            max_idle,
            circuits: Mutex::new(HashMap::new()),
        }
    }

    /// Circuit state for an upstream (for /health reporting).
    pub fn circuit_state(&self, upstream: &str) -> &'static str {
        let circuits = self.circuits.lock().unwrap();
        circuits.get(upstream).map(|cb| cb.state_name()).unwrap_or("closed")
    }

    /// Acquire a connection to the named upstream.
    /// Checks the circuit breaker first — returns Err(NoHealthySlot) if open.
    /// Pops an idle connection if available and non-expired, otherwise opens a new one.
    pub fn acquire(&self, target: &'static UpstreamTarget) -> Result<ConnGuard, PoolError> {
        // ── Circuit breaker check ─────────────────────────────────────────────
        {
            let mut circuits = self.circuits.lock().unwrap();
            let cb = circuits.entry(target.name).or_insert_with(|| CircuitBreaker::new(target.name));
            match cb.check() {
                CircuitDecision::Allow => {}
                CircuitDecision::Reject { reason } => {
                    eprintln!("[pool] circuit {}: rejected — {}", target.name, reason);
                    crate::metrics::metrics().record_rate_limited(); // reuse the rate-limited counter for circuit-blocked
                    return Err(PoolError::NoHealthySlot);
                }
            }
        }

        // ── Try to pop an idle connection ─────────────────────────────────────
        {
            let mut pools = self.pools.lock().unwrap();
            let queue     = pools.entry(target.name).or_default();
            // Drain expired connections from the back
            while let Some(conn) = queue.last() {
                if conn.is_expired() {
                    queue.pop(); // PooledConn::drop closes the fd
                } else {
                    break;
                }
            }
            if let Some(conn) = queue.pop() {
                // Idle reuse counts as a success for the circuit breaker
                self.circuits.lock().unwrap()
                    .get(target.name)
                    .map(|cb| cb.record(Outcome::Success));
                return Ok(ConnGuard {
                    inner:   Some(conn),
                    pool:    self as *const ConnPool,
                    healthy: true,
                });
            }
        }

        // ── No idle connection — open a new one ───────────────────────────────
        match self.open_connection(target) {
            Ok(guard) => {
                self.circuits.lock().unwrap()
                    .get(target.name)
                    .map(|cb| cb.record(Outcome::Success));
                Ok(guard)
            }
            Err(e) => {
                self.circuits.lock().unwrap()
                    .get(target.name)
                    .map(|cb| cb.record(Outcome::Failure));
                Err(e)
            }
        }
    }

    fn open_connection(&self, target: &'static UpstreamTarget) -> Result<ConnGuard, PoolError> {
        // TCP connect (blocking for simplicity — async connect is handled by the executor)
        let fd = tcp_connect(target.host, target.port)
            .map_err(PoolError::ConnectFailed)?;

        // Track new connection in metrics
        crate::metrics::metrics().record_pool_connection();

        if !target.tls {
            // No TLS — wrap in a dummy AppKeys (local upstreams / plain HTTP)
            let dummy_keys = dummy_app_keys();
            let conn = PooledConn::new(fd, dummy_keys, target.name, false);
            return Ok(ConnGuard { inner: Some(conn), pool: self as *const ConnPool, healthy: true });
        }

        // Real TLS 1.3 handshake — drives the ClientHandshake FSM in tls/handshake.rs.
        // On failure, the TcpStream inside run_client_tls_handshake drops and closes fd.
        let (tls_fd, app_keys) = run_client_tls_handshake(fd, target.host)
            .map_err(|e| {
                eprintln!("[pool] TLS to {} failed: {}", target.name, e);
                e
            })?;
        let conn = PooledConn::new(tls_fd, app_keys, target.name, false);
        Ok(ConnGuard { inner: Some(conn), pool: self as *const ConnPool, healthy: true })
    }

    fn return_conn(&self, conn: PooledConn) {
        let mut pools = self.pools.lock().unwrap();
        let queue = pools.entry(conn.upstream).or_default();
        if queue.len() < self.max_idle {
            queue.push(conn);
        }
        // else: conn is dropped here, closing the fd
    }

    /// Number of idle connections for a given upstream.
    pub fn idle_count(&self, upstream: &str) -> usize {
        let pools = self.pools.lock().unwrap();
        pools.get(upstream).map(|q| q.len()).unwrap_or(0)
    }
}

unsafe impl Send for ConnPool {}
unsafe impl Sync for ConnPool {}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Open a blocking TCP connection to `host:port`.  Returns the socket fd.
fn tcp_connect(host: &str, port: u16) -> std::io::Result<RawFd> {
    use std::net::TcpStream;
    use std::os::unix::io::IntoRawFd;
    let stream = TcpStream::connect((host, port))?;
    stream.set_nodelay(true)?;
    Ok(stream.into_raw_fd())
}

/// Placeholder AppKeys for plain-HTTP (non-TLS) upstream connections.
/// The keys are all-zeros — the pipeline checks `has_tls()` before using them.
fn dummy_app_keys() -> AppKeys {
    use crate::tls::keys::TrafficKeys;
    AppKeys {
        client:        TrafficKeys { key: vec![0u8; 16], iv: vec![0u8; 12] },
        server:        TrafficKeys { key: vec![0u8; 16], iv: vec![0u8; 12] },
        master_secret: [0u8; 32],
    }
}

// ── TLS 1.3 client handshake ─────────────────────────────────────────────────

/// Read one complete TLS record from `stream`.
///
/// Returns `(outer_content_type_byte, full_record_including_5_byte_header)`.
/// The outer type for TLS 1.3 application-data records is 0x17; handshake is 0x16.
fn read_tls_record(stream: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let payload_len = ((header[3] as usize) << 8) | header[4] as usize;
    // TLS 1.3 max plaintext 2^14 + AEAD overhead (~256 bytes)
    const MAX_TLS_RECORD: usize = 16_640;
    if payload_len > MAX_TLS_RECORD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS record payload too large",
        ));
    }
    let mut full = Vec::with_capacity(5 + payload_len);
    full.extend_from_slice(&header);
    full.resize(5 + payload_len, 0);
    stream.read_exact(&mut full[5..])?;
    Ok((header[0], full))
}

/// Scan a buffer of concatenated TLS 1.3 handshake messages for a Finished message
/// (message type 20 per RFC 8446).
fn has_finished_msg(data: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let msg_type = data[offset];
        let msg_len  = ((data[offset + 1] as usize) << 16)
                     | ((data[offset + 2] as usize) <<  8)
                     |   data[offset + 3] as usize;
        if msg_type == 20 { return true; }   // MSG_FINISHED
        let next = offset + 4 + msg_len;
        if next <= offset { break; }          // guard against zero-length infinite loop
        offset = next;
    }
    false
}

/// Perform a full TLS 1.3 client handshake on the connected socket `fd`.
///
/// Uses the `ClientHandshake` FSM in `tls/handshake.rs`:
///   1. Send ClientHello.
///   2. Read plaintext records until ServerHello (0x16), skipping CCS (0x14).
///   3. Derive HandshakeKeys via `process_server_hello()`.
///   4. Build a server-read `RecordLayer` from the HS keys.
///   5. Read and decrypt the server's encrypted flight
///      (EncryptedExtensions → Certificate → CertificateVerify → Finished).
///   6. Call `build_client_finished()` → encrypted ClientFinished bytes + AppKeys.
///   7. Send encrypted ClientFinished; return `(fd, app_keys)`.
///
/// Certificate verification is skipped in this release — a pinned-cert check
/// or system-trust-store validation is planned for Phase 2.
fn run_client_tls_handshake(fd: RawFd, _server_name: &str) -> Result<(RawFd, AppKeys), PoolError> {
    // Take ownership of the raw fd.  If we return Err, TcpStream::drop closes it.
    let mut stream = unsafe { TcpStream::from_raw_fd(fd) };

    let mut hs = ClientHandshake::new();

    // ── 1. Send ClientHello ───────────────────────────────────────────────────
    let client_hello = hs.build_client_hello()
        .map_err(|_| PoolError::TlsFailed("build_client_hello"))?;
    stream.write_all(&client_hello)
        .map_err(|_| PoolError::TlsFailed("send ClientHello"))?;

    // ── 2. Read ServerHello ───────────────────────────────────────────────────
    // Skip ChangeCipherSpec (0x14) compat records; break on Handshake (0x16).
    let server_hello_msg = loop {
        let (rec_type, record) = read_tls_record(&mut stream)
            .map_err(|_| PoolError::TlsFailed("read ServerHello record"))?;
        match rec_type {
            0x14 => continue,                      // CCS — TLS 1.2 compat, ignore
            0x15 => return Err(PoolError::TlsFailed("TLS alert before ServerHello")),
            0x16 => break record[5..].to_vec(),    // Handshake record → payload = HS msg
            _    => return Err(PoolError::TlsFailed("unexpected record type before ServerHello")),
        }
    };

    // ── 3. Process ServerHello → HandshakeKeys ────────────────────────────────
    let hs_keys = hs.process_server_hello(&server_hello_msg)
        .map_err(|_| PoolError::TlsFailed("process_server_hello"))?;

    // ── 4. Build RecordLayer for server's encrypted flight ────────────────────
    // We write with client HS keys (for ClientFinished later),
    // we read with server HS keys (to decrypt the server flight).
    let mut rl = RecordLayer::new(CipherSuite::Aes128Gcm, &hs_keys.client, &hs_keys.server)
        .map_err(|_| PoolError::TlsFailed("RecordLayer::new"))?;

    // ── 5. Read + decrypt server's encrypted handshake flight ─────────────────
    // Flight = EncryptedExtensions + Certificate + CertificateVerify + Finished.
    // Each record is an ApplicationData (0x17) outer type; inner type is Handshake.
    let mut decrypted_flight: Vec<u8> = Vec::new();
    loop {
        let (rec_type, mut record) = read_tls_record(&mut stream)
            .map_err(|_| PoolError::TlsFailed("read server encrypted flight"))?;
        match rec_type {
            0x14 => continue,  // CCS compat
            0x15 => return Err(PoolError::TlsFailed("TLS alert in server flight")),
            0x17 => {
                // Decrypt the record; copy plaintext out so the borrow on `record` ends.
                let (inner_type, plaintext_owned) = {
                    let (inner, plain) = rl.open(&mut record)
                        .map_err(|_| PoolError::TlsFailed("decrypt server flight record"))?;
                    (inner, plain.to_vec())
                };
                match inner_type {
                    ContentType::Handshake => {
                        decrypted_flight.extend_from_slice(&plaintext_owned);
                    }
                    ContentType::Alert => {
                        return Err(PoolError::TlsFailed("TLS alert (encrypted) in server flight"));
                    }
                    _ => {} // ignore ApplicationData and other inner types
                }
                if has_finished_msg(&decrypted_flight) { break; }
                if decrypted_flight.len() > 131_072 {
                    return Err(PoolError::TlsFailed("server handshake flight too large"));
                }
            }
            _ => return Err(PoolError::TlsFailed("unexpected outer record type in server flight")),
        }
    }

    // ── 6. Build ClientFinished + derive AppKeys ──────────────────────────────
    let (fin_wrapped, app_keys) = hs.build_client_finished(&decrypted_flight)
        .map_err(|_| PoolError::TlsFailed("build_client_finished"))?;

    // fin_wrapped = wrap_handshake_record(fin_msg) = [0x16, 0x03, 0x03, len_hi, len_lo, msg...]
    // Encrypt the handshake message (after 5-byte TLS record header) with client HS key.
    if fin_wrapped.len() <= 5 {
        return Err(PoolError::TlsFailed("ClientFinished record unexpectedly short"));
    }
    let fin_encrypted = rl.seal(ContentType::Handshake, &fin_wrapped[5..])
        .map_err(|_| PoolError::TlsFailed("seal ClientFinished"))?;
    stream.write_all(&fin_encrypted)
        .map_err(|_| PoolError::TlsFailed("send ClientFinished"))?;

    // ── 7. Return fd and application keys ─────────────────────────────────────
    // TODO: pin server certificate or validate against system trust store (Phase 2)
    eprintln!("[tls] handshake complete with upstream (cert verification: Phase 2)");
    let new_fd = stream.into_raw_fd(); // release ownership without closing
    Ok((new_fd, app_keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::resolve_named;

    #[test]
    fn pool_idle_count_starts_zero() {
        let pool = ConnPool::new(8);
        assert_eq!(pool.idle_count("openai"), 0);
    }
}
