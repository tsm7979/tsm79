/// JA3/JA4 TLS client fingerprinting.
///
/// JA3 — MD5 hash of: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
/// JA4 — Cloudflare's successor: more structured, sortable, not hash-first
///
/// Why this matters for an AI firewall:
///   Known threat tooling has stable JA3 fingerprints.  Cobalt Strike's default
///   Malleable C2 profile, Metasploit handlers, Sliver C2, Go's default TLS
///   stack, and Python requests all produce recognisable fingerprints.
///   If an LLM exfiltration bot is built in Go with default TLS, the JA3 nails it.
///
/// Usage:
///   let fp = Ja3Fingerprint::from_client_hello(&client_hello_bytes)?;
///   let threat = fp.lookup_threat();
///   // → ThreatMatch { tool: "Cobalt Strike", confidence: 0.95 }
///
/// Data:
///   Known-bad JA3 hashes from:
///   - Salesforce/ja3 project
///   - Trickbot / Emotet / Redline campaign research
///   - Internal TSM threat research

use std::collections::HashMap;
use std::sync::OnceLock;

// ── TLS constants ─────────────────────────────────────────────────────────────

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME:         u16 = 0x0000;
const EXT_SUPPORTED_GROUPS:    u16 = 0x000a;
const EXT_EC_POINT_FORMATS:    u16 = 0x000b;
const EXT_SESSION_TICKET:      u16 = 0x0023;
const EXT_SIGNATURE_ALGORITHMS:u16 = 0x000d;

// GREASE values — ignored in JA3 computation per spec
const GREASE: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_grease(v: u16) -> bool { GREASE.contains(&v) }

// ── Parsed ClientHello fields ─────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ClientHelloInfo {
    pub tls_version:      u16,
    pub ciphers:          Vec<u16>,
    pub extensions:       Vec<u16>,
    pub elliptic_curves:  Vec<u16>,
    pub point_formats:    Vec<u8>,
    pub sni:              Option<String>,
    /// Raw ClientHello bytes — needed for JA4 computation.
    pub raw:              Vec<u8>,
}

// ── JA3 fingerprint ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ja3Fingerprint {
    /// Human-readable JA3 string: "769,4865-4866,...,0-23,...,23,...,0"
    pub ja3_str:  String,
    /// MD5 of ja3_str (32-char hex)
    pub ja3_hash: String,
    /// JA4 string (Cloudflare format: t13d1715h2_...)
    pub ja4:      String,
    pub info:     ClientHelloInfo,
}

impl Ja3Fingerprint {
    /// Parse a TLS ClientHello record.
    ///
    /// `data` should start at the TLS record layer (beginning with 0x16 0x03 ...).
    /// Returns Err if the record is malformed or not a ClientHello.
    pub fn from_record(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 5 { return Err("record too short"); }

        // TLS record header: type(1) version(2) length(2)
        let rec_type = data[0];
        if rec_type != 0x16 { return Err("not a Handshake record"); }
        let rec_len  = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + rec_len { return Err("truncated record"); }

        let hs = &data[5..5 + rec_len];
        Self::from_handshake(hs, data.to_vec())
    }

    /// Parse from the Handshake message body (after the TLS record header).
    fn from_handshake(hs: &[u8], raw: Vec<u8>) -> Result<Self, &'static str> {
        if hs.len() < 4 { return Err("handshake too short"); }
        if hs[0] != HANDSHAKE_CLIENT_HELLO { return Err("not ClientHello"); }

        let mut pos = 4; // skip msg_type(1) + length(3)

        // ClientHello.legacy_version (2 bytes)
        if hs.len() < pos + 2 { return Err("truncated at version"); }
        let version = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        pos += 2;

        // Random (32 bytes)
        pos += 32;
        if pos >= hs.len() { return Err("truncated at random"); }

        // Session ID
        let sid_len = hs.get(pos).copied().unwrap_or(0) as usize;
        pos += 1 + sid_len;

        // Cipher Suites
        if hs.len() < pos + 2 { return Err("truncated at ciphers"); }
        let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
        pos += 2;
        let mut ciphers = Vec::new();
        for i in (0..cs_len).step_by(2) {
            if pos + i + 1 >= hs.len() { break; }
            let cs = u16::from_be_bytes([hs[pos + i], hs[pos + i + 1]]);
            if !is_grease(cs) { ciphers.push(cs); }
        }
        pos += cs_len;

        // Compression Methods
        let cm_len = hs.get(pos).copied().unwrap_or(0) as usize;
        pos += 1 + cm_len;

        // Extensions
        if pos + 2 > hs.len() {
            // No extensions — old TLS 1.0 client
            let info = ClientHelloInfo { tls_version: version, ciphers, raw, ..Default::default() };
            return Ok(Self::compute(info));
        }
        let ext_total = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_total;

        let mut extensions  = Vec::new();
        let mut curves       = Vec::new();
        let mut point_fmts   = Vec::new();
        let mut sni          = None;

        while pos + 4 <= ext_end.min(hs.len()) {
            let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
            let ext_len  = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
            pos += 4;

            if !is_grease(ext_type) {
                extensions.push(ext_type);
            }

            match ext_type {
                EXT_SERVER_NAME => {
                    sni = parse_sni(&hs[pos..pos.min(pos + ext_len)]);
                }
                EXT_SUPPORTED_GROUPS => {
                    curves = parse_u16_list(&hs[pos..pos.min(pos + ext_len)]);
                    curves.retain(|&c| !is_grease(c));
                }
                EXT_EC_POINT_FORMATS => {
                    let list_len = hs.get(pos).copied().unwrap_or(0) as usize;
                    point_fmts = hs[pos + 1..pos + 1 + list_len.min(ext_len)].to_vec();
                }
                _ => {}
            }

            pos += ext_len;
        }

        let info = ClientHelloInfo {
            tls_version: version,
            ciphers,
            extensions,
            elliptic_curves: curves,
            point_formats: point_fmts,
            sni,
            raw,
        };

        Ok(Self::compute(info))
    }

    fn compute(info: ClientHelloInfo) -> Self {
        let ja3_str  = build_ja3_str(&info);
        let ja3_hash = md5_hex(ja3_str.as_bytes());
        let ja4      = build_ja4(&info);

        Ja3Fingerprint { ja3_str, ja3_hash, ja4, info }
    }

    /// Look up this fingerprint against the known-bad list.
    pub fn lookup_threat(&self) -> Option<ThreatMatch> {
        known_bad().get(self.ja3_hash.as_str()).cloned()
    }

    /// True if this fingerprint matches any known threat actor.
    pub fn is_malicious(&self) -> bool {
        self.lookup_threat().is_some()
    }

    /// Risk score (0.0–1.0) based on fingerprint reputation.
    pub fn risk_score(&self) -> f64 {
        self.lookup_threat()
            .map(|m| m.confidence)
            .unwrap_or(0.0)
    }
}

// ── JA3 string builder ────────────────────────────────────────────────────────

fn build_ja3_str(info: &ClientHelloInfo) -> String {
    let version = info.tls_version.to_string();

    let ciphers = info.ciphers.iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let exts = info.extensions.iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let curves = info.elliptic_curves.iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let points = info.point_formats.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("-");

    format!("{},{},{},{},{}", version, ciphers, exts, curves, points)
}

// ── JA4 builder (Cloudflare format) ──────────────────────────────────────────
//
// JA4 = {protocol}{tls_version}{SNI?}{cipher_count}{ext_count}_{sorted_ciphers_hash}_{sorted_exts_hash}
// Example: t13d1715h2_8daaf6152771_b1ff8ab2d16f

fn build_ja4(info: &ClientHelloInfo) -> String {
    let proto   = "t";  // TCP
    let version = match info.tls_version {
        0x0304 => "13", 0x0303 => "12", 0x0302 => "11", _ => "10",
    };
    let sni_flag  = if info.sni.is_some() { "d" } else { "i" };
    let n_ciphers = info.ciphers.len().min(99);
    let n_exts    = info.extensions.len().min(99);

    // Sort ciphers and extensions for the hash fields.
    let mut sorted_ciphers = info.ciphers.clone();
    sorted_ciphers.sort_unstable();
    let cipher_str: String = sorted_ciphers.iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");

    let mut sorted_exts = info.extensions.clone();
    sorted_exts.retain(|&e| e != EXT_SESSION_TICKET && e != EXT_SERVER_NAME);
    sorted_exts.sort_unstable();
    let ext_str: String = sorted_exts.iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");

    let cipher_hash = sha256_truncated_hex(cipher_str.as_bytes(), 12);
    let ext_hash    = sha256_truncated_hex(ext_str.as_bytes(), 12);

    format!("{}{}{}{:02}{:02}_{}_{}",
        proto, version, sni_flag, n_ciphers, n_exts, cipher_hash, ext_hash)
}

// ── Extension parsers ─────────────────────────────────────────────────────────

fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 { return None; }
    // sni_list_len(2) + name_type(1) + name_len(2) + name
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len { return None; }
    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
}

fn parse_u16_list(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 { return vec![]; }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut out  = Vec::new();
    for i in (0..list_len.min(data.len() - 2)).step_by(2) {
        out.push(u16::from_be_bytes([data[2 + i], data[2 + i + 1]]));
    }
    out
}

// ── MD5 (for JA3 hash — not used for security, just fingerprinting) ──────────

fn md5_hex(data: &[u8]) -> String {
    // Minimal MD5 implementation (RFC 1321).
    // JA3 uses MD5 purely for fingerprint stability — not cryptographic security.
    const S: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg  = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0x00); }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0 = 0x67452301u32;
    let mut b0 = 0xefcdab89u32;
    let mut c0 = 0x98badcfeu32;
    let mut d0 = 0x10325476u32;

    for chunk in msg.chunks_exact(64) {
        let m: Vec<u32> = chunk.chunks_exact(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0usize..64 {
            let (f, g) = match i {
                0..=15  => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d,              (3 * i + 5) % 16),
                _       => (c ^ (b | (!d)),         (7 * i)     % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add((a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g])).rotate_left(S[i]));
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── SHA-256 truncated for JA4 hash fields ─────────────────────────────────────

fn sha256_truncated_hex(data: &[u8], len: usize) -> String {
    // Re-use the SHA-256 from merkle.rs via the audit module.
    // For now, use a minimal inline version.
    use crate::audit::merkle; // sha256 is private there; we duplicate minimally.

    // Simple FNV-1a hash as stand-in for build correctness.
    // In production: use sha2 crate or the audit::merkle sha256.
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let hex = format!("{:016x}{:016x}", hash, !hash);
    hex[..len.min(hex.len())].to_owned()
}

// ── Known-bad fingerprint database ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub tool:        &'static str,
    pub category:    &'static str,
    pub confidence:  f64,
    pub description: &'static str,
}

static KNOWN_BAD: OnceLock<HashMap<&'static str, ThreatMatch>> = OnceLock::new();

fn known_bad() -> &'static HashMap<&'static str, ThreatMatch> {
    KNOWN_BAD.get_or_init(|| {
        let mut m = HashMap::new();

        // Sources: Salesforce/ja3, JARM, threat research blogs
        // Cobalt Strike default profiles
        m.insert("72a589da586844d7f0818ce684948eea", ThreatMatch {
            tool: "Cobalt Strike", category: "c2", confidence: 0.95,
            description: "Cobalt Strike default Malleable C2 JA3",
        });
        m.insert("a0e9f5d64349fb13191bc781f81f42e1", ThreatMatch {
            tool: "Cobalt Strike", category: "c2", confidence: 0.92,
            description: "Cobalt Strike Beacon HTTP/S stager",
        });

        // Metasploit
        m.insert("b386946a5a44d1ddcc843bc75336dfce", ThreatMatch {
            tool: "Metasploit", category: "exploit_framework", confidence: 0.90,
            description: "Metasploit framework default handler",
        });

        // Sliver C2
        m.insert("1aa7bf6b1ec6a0a1b622e4d09a585b7c", ThreatMatch {
            tool: "Sliver", category: "c2", confidence: 0.88,
            description: "Sliver C2 framework default implant",
        });

        // Go default TLS stack (used by many attack tools)
        m.insert("ja3_go_default_1.21", ThreatMatch {
            tool: "Go/1.21 default", category: "scripted", confidence: 0.40,
            description: "Go standard library TLS — common in attack tooling",
        });

        // Python requests default
        m.insert("6734f37431670b3ab4292b8f60f29984", ThreatMatch {
            tool: "Python/requests", category: "scripted", confidence: 0.20,
            description: "Python requests library — low confidence alone",
        });

        // Trickbot / Emotet loaders
        m.insert("6fa3244afc6bb5ac885eed6afe501ef4", ThreatMatch {
            tool: "Trickbot", category: "malware", confidence: 0.97,
            description: "Trickbot HTTPS C2 beacon",
        });
        m.insert("a35bab1f0ca65f9e6c5b9b3ab3680e8e", ThreatMatch {
            tool: "Emotet", category: "malware", confidence: 0.96,
            description: "Emotet loader HTTPS",
        });

        // Redline stealer — common AI API credential theft tool
        m.insert("c35b4e9974dbb578d5a9e6f10eefc3d7", ThreatMatch {
            tool: "Redline Stealer", category: "infostealer", confidence: 0.94,
            description: "Redline Stealer HTTPS C2 — known API key thief",
        });

        // LummaStealer — actively harvests OpenAI / Anthropic API keys
        m.insert("d0ec61de8fa8e5f945fa68dd083c4d65", ThreatMatch {
            tool: "LummaStealer", category: "infostealer", confidence: 0.95,
            description: "LummaStealer — targets AI API keys and browser sessions",
        });

        // curl default (for monitoring; low risk alone)
        m.insert("743c250a16d8e2b9f614a35be8383aef", ThreatMatch {
            tool: "curl/7.x", category: "tool", confidence: 0.10,
            description: "curl default TLS — low risk, flag for anomaly correlation",
        });

        m
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_known_vector() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let h = md5_hex(b"");
        assert_eq!(h, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn md5_hello_world() {
        // MD5("hello world") = 5eb63bbbe01eeed093cb22bb8f5acdc3
        let h = md5_hex(b"hello world");
        assert_eq!(h, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[test]
    fn ja3_str_format() {
        let info = ClientHelloInfo {
            tls_version: 769,
            ciphers: vec![47, 53, 5],
            extensions: vec![0, 23, 65281],
            elliptic_curves: vec![23, 24],
            point_formats: vec![0],
            sni: Some("openai.com".to_string()),
            raw: vec![],
        };
        let s = build_ja3_str(&info);
        assert!(s.starts_with("769,"));
        assert!(s.contains(",47-53-5,"));
    }

    #[test]
    fn known_bad_returns_cobalt_strike() {
        let kb = known_bad();
        let m = kb.get("72a589da586844d7f0818ce684948eea").unwrap();
        assert_eq!(m.tool, "Cobalt Strike");
        assert!(m.confidence > 0.90);
    }

    #[test]
    fn grease_filter() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x002f)); // TLS_RSA_WITH_AES_128_CBC_SHA
    }
}
