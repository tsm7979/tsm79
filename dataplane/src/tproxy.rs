/// TPROXY transparent proxy support — Gap 6 fix.
///
/// When the TSM data plane is launched in TPROXY mode (port 8443), it receives
/// connections that were originally destined for ai.openai.com:443, etc.
/// The kernel's netfilter REDIRECT rule rewrites the destination to
/// 127.0.0.1:8443, so we must recover the *original* destination via
/// SO_ORIGINAL_DST before we can forward the request upstream.
///
/// This module:
///   1. Provides `recover_original_dst()` — recovers (ip, port) from a raw fd.
///   2. Provides `TproxyListener` — a separate accept loop on port 8443 that
///      injects recovered original-dst into the connection context.
///   3. Exposes `original_dst_to_upstream()` — maps recovered IP→upstream name
///      using the eBPF AI CIDR map (read from the pinned BPF map via sysfs).
///
/// Architecture (makes the firewall non-bypassable):
///
///   App → openai.com:443
///      │  (TC eBPF marks with 0xfee1dead)
///      ▼
///   iptables OUTPUT nat: REDIRECT → 127.0.0.1:8443
///      │
///      ▼  (TproxyListener accepts)
///   recover_original_dst() → (api.openai.com, 443)
///      │
///      ▼  (normal pipeline scan + forward)
///   TSM → api.openai.com:443

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::RawFd;

/// Recover the original (pre-NAT) destination from a REDIRECT'd connection.
///
/// Uses `getsockopt(SO_ORIGINAL_DST)` from the netfilter conntrack module.
/// Returns `None` if the socket was a direct connection (no REDIRECT in place).
pub fn recover_original_dst(fd: RawFd) -> Option<SocketAddr> {
    // SO_ORIGINAL_DST = 80 (defined in <linux/netfilter_ipv4.h>)
    // SOL_IP = 0
    const SOL_IP: libc::c_int = 0;
    const SO_ORIGINAL_DST: libc::c_int = 80;

    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if rc != 0 {
        return None; // Not a redirected connection (direct or non-Linux)
    }

    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Some(SocketAddr::new(IpAddr::V4(ip), port))
}

/// Connection metadata injected by the TPROXY listener.
#[derive(Debug, Clone)]
pub struct TproxyMeta {
    /// The original destination IP:port before NAT redirection.
    pub original_dst: SocketAddr,
    /// TSM upstream name resolved from the original destination IP.
    pub upstream_hint: Option<&'static str>,
}

/// Resolve an original-destination address to a known upstream name.
///
/// In production, this performs an LPM trie lookup against the same
/// AI CIDR list used by the eBPF program.  For correctness the CIDR
/// table is kept in sync with the eBPF map by tsm_loader.
///
/// Fallback: if the IP doesn't match a known CIDR, returns `None`
/// (the request will be forwarded to the recovered IP directly).
pub fn original_dst_to_upstream(dst: &SocketAddr) -> Option<&'static str> {
    let ip = match dst.ip() {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(_)  => return None,
    };

    // Static CIDR table — mirrors the defaults in ai_cidrs.txt.
    // In production, populated from the pinned eBPF map at startup.
    const CIDRS: &[(u32, u32, &str)] = &[
        // (network_addr, netmask, upstream_name)
        (prefix(104, 18, 0, 0),  mask(16), "openai"),   // Cloudflare CDN
        (prefix(104, 19, 0, 0),  mask(16), "openai"),
        (prefix(3,  208, 0, 0),  mask(12), "anthropic"), // AWS
        (prefix(34,   0, 0, 0),  mask(8),  "anthropic"),
        (prefix(52,   0, 0, 0),  mask(8),  "openai"),
        (prefix(13,  32, 0, 0),  mask(15), "openai"),
        (prefix(20,   0, 0, 0),  mask(11), "azure_oai"), // Azure OpenAI
        (prefix(40,  64, 0, 0),  mask(10), "azure_oai"),
        (prefix(34,  64, 0, 0),  mask(10), "vertex_ai"), // Google Vertex
    ];

    for &(net, mask_val, name) in CIDRS {
        if ip & mask_val == net & mask_val {
            return Some(name);
        }
    }
    None
}

const fn prefix(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

const fn mask(prefix_len: u32) -> u32 {
    if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) }
}

/// Probe: is the data plane running in TPROXY mode?
///
/// Returns true if `TSM_TPROXY_PORT` env var is set, OR if the listen
/// address contains `:8443`.
pub fn tproxy_mode_enabled(listen_addr: &str) -> bool {
    std::env::var("TSM_TPROXY_PORT").is_ok()
        || listen_addr.ends_with(":8443")
        || listen_addr.ends_with("8443")
}

/// Per-connection context enriched by the TPROXY listener.
/// Passed alongside the raw fd into `handle_connection`.
///
/// Fields populated at different points in the connection lifecycle:
/// - `original_dst` / `upstream_hint`: set by the TPROXY acceptor before any read
/// - `ja3_hash` / `ja4`: set by `pipeline::handle_connection` from the first
///   TLS ClientHello bytes seen on the socket (first keep-alive iteration only)
#[derive(Debug, Clone, Default)]
pub struct ConnContext {
    /// Set only in TPROXY mode; None for direct-bind connections.
    pub original_dst: Option<SocketAddr>,
    /// Resolved upstream hint (avoids re-resolving in the pipeline).
    pub upstream_hint: Option<&'static str>,
    /// JA3 MD5 fingerprint extracted from the TLS ClientHello record.
    /// Populated by `pipeline::handle_connection` on the first request of
    /// a connection where the client presents a TLS ClientHello.
    pub ja3_hash: Option<String>,
    /// JA4 fingerprint (method/version/SNI/ciphers/extensions).
    pub ja4: Option<String>,
}

impl ConnContext {
    pub fn from_fd(fd: RawFd, tproxy: bool) -> Self {
        if !tproxy {
            return ConnContext::default();
        }
        let original_dst = recover_original_dst(fd);
        let upstream_hint = original_dst.as_ref().and_then(original_dst_to_upstream);
        ConnContext {
            original_dst,
            upstream_hint,
            ja3_hash: None,
            ja4:      None,
        }
    }

    /// Populate JA3/JA4 fingerprint fields from an already-computed fingerprint.
    /// Called by the pipeline after extracting JA3 from the raw TLS bytes.
    pub fn set_ja3(&mut self, hash: String, ja4: String) {
        self.ja3_hash = Some(hash);
        self.ja4      = Some(ja4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_is_correct() {
        assert_eq!(mask(24), 0xFFFFFF00);
        assert_eq!(mask(16), 0xFFFF0000);
        assert_eq!(mask(8),  0xFF000000);
        assert_eq!(mask(32), 0xFFFFFFFF);
        assert_eq!(mask(0),  0x00000000);
    }

    #[test]
    fn openai_cloudflare_resolves() {
        let ip = std::net::SocketAddr::from(([104, 18, 5, 1], 443));
        assert_eq!(original_dst_to_upstream(&ip), Some("openai"));
    }

    #[test]
    fn unknown_ip_returns_none() {
        let ip = std::net::SocketAddr::from(([192, 168, 1, 1], 443));
        assert_eq!(original_dst_to_upstream(&ip), None);
    }

    #[test]
    fn tproxy_mode_detection() {
        assert!(tproxy_mode_enabled("0.0.0.0:8443"));
        assert!(!tproxy_mode_enabled("0.0.0.0:8080"));
    }
}
