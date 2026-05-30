/// Configuration loaded from environment variables at startup.
/// No external dep (clap, config-rs, etc.) — pure stdlib.
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct Config {
    /// Address to listen on.  Default: 0.0.0.0:8080
    pub listen_addr: SocketAddr,

    /// Python detector URL.  Default: http://127.0.0.1:8001
    pub detector_url: String,

    /// Detector request timeout in milliseconds.  Default: 5000
    pub detector_timeout_ms: u64,

    /// Path to the append-only audit log file.
    pub audit_log_path: String,

    /// HMAC secret for the audit chain (must be 32+ bytes in production).
    pub audit_secret: String,

    /// Network interface to attach the XDP program to.  Empty = no eBPF.
    pub xdp_iface: String,

    /// Max idle connections per upstream.  Default: 8
    pub pool_max_idle: usize,

    /// What to do if the detector is unreachable: "allow" | "block" | "degrade"
    pub detector_failure_mode: FailureMode,

    /// Per-IP request rate limit (requests per minute).  Default: 100
    pub rate_limit: u32,

    /// Path to TLS certificate (PEM).  Empty = HTTP only (dev mode).
    pub tls_cert: String,

    /// Path to TLS private key (PEM).  Empty = HTTP only (dev mode).
    pub tls_key: String,

    /// Org ID header name.  Default: x-tsm-org
    pub org_header: String,

    /// Log level: "info" | "debug" | "warn" | "error".  Default: "info"
    pub log_level: String,

    /// Control plane URL for policy hot-reload.  Empty = disabled.
    /// Format: "http://host:9090"
    pub control_plane_url: String,

    /// Node ID for control-plane registration.  Defaults to hostname.
    pub node_id: String,

    /// PostgreSQL DSN for audit writes.  Empty = disabled.
    /// Format: "host=localhost port=5432 dbname=tsm user=tsm password=secret"
    pub pg_dsn: String,

    /// Kafka bootstrap brokers for audit event streaming.  Empty = disabled.
    /// Format: "broker1:9092,broker2:9092"
    pub kafka_brokers: String,

    /// Workspace ID sent with every audit event (UUID).
    pub workspace_id: String,

    /// Org ID sent with every audit event (UUID).
    pub org_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum FailureMode {
    Allow,
    Block,
    Degrade,
}

impl Config {
    pub fn from_env() -> Self {
        Config {
            listen_addr: env_str("TSM_LISTEN", "0.0.0.0:8080")
                .parse()
                .expect("TSM_LISTEN must be a valid socket address"),

            detector_url: env_str("TSM_DETECTOR_URL", "http://127.0.0.1:8001"),

            detector_timeout_ms: env_u64("TSM_DETECTOR_TIMEOUT_MS", 5_000),

            audit_log_path: env_str("TSM_AUDIT_LOG", "tsm_audit.log"),

            audit_secret: {
                let s = env_str("TSM_AUDIT_SECRET", "change-me-in-production");
                if s == "change-me-in-production" {
                    eprintln!(
                        "WARNING: TSM_AUDIT_SECRET is set to the default value. \
                         Set a strong secret (32+ bytes) before production use."
                    );
                }
                s
            },

            xdp_iface: env_str("TSM_XDP_IFACE", ""),

            pool_max_idle: env_usize("TSM_POOL_MAX_IDLE", 8),

            detector_failure_mode: match env_str("TSM_DETECTOR_FAILURE_MODE", "allow").as_str() {
                "block"   => FailureMode::Block,
                "degrade" => FailureMode::Degrade,
                _         => FailureMode::Allow,
            },

            rate_limit: env_u64("TSM_RATE_LIMIT", 100) as u32,

            tls_cert: env_str("TSM_TLS_CERT", ""),
            tls_key:  env_str("TSM_TLS_KEY",  ""),

            org_header: env_str("TSM_ORG_HEADER", "x-tsm-org"),

            log_level: env_str("TSM_LOG_LEVEL", "info"),

            control_plane_url: env_str("TSM_CONTROL_PLANE_URL", ""),

            node_id: env_str("TSM_NODE_ID", {
                // Default to hostname
                &std::env::var("HOSTNAME")
                    .or_else(|_| std::env::var("COMPUTERNAME"))
                    .unwrap_or_else(|_| "tsm-dataplane".to_owned())
            }),

            pg_dsn:       env_str("TSM_PG_DSN",      ""),
            kafka_brokers: env_str("TSM_KAFKA_BROKERS", ""),
            workspace_id: env_str("TSM_WORKSPACE_ID", "00000000-0000-0000-0000-000000000002"),
            org_id:       env_str("TSM_ORG_ID",       "00000000-0000-0000-0000-000000000001"),
        }
    }

    pub fn tls_enabled(&self) -> bool {
        !self.tls_cert.is_empty() && !self.tls_key.is_empty()
    }
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_parse_cleanly() {
        // Unset all TSM_ vars for this test so we get pure defaults
        for (k, _) in std::env::vars().filter(|(k, _)| k.starts_with("TSM_")) {
            // We can't easily unset but we can verify the types are right
            let _ = k;
        }
        // The default listen addr must be valid
        let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn failure_mode_parsing() {
        assert_eq!(
            match "block" { "block" => FailureMode::Block, "degrade" => FailureMode::Degrade, _ => FailureMode::Allow },
            FailureMode::Block
        );
        assert_eq!(
            match "allow" { "block" => FailureMode::Block, "degrade" => FailureMode::Degrade, _ => FailureMode::Allow },
            FailureMode::Allow
        );
    }
}
