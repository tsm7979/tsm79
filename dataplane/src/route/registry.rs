/// Upstream routing registry.
///
/// Maps AI model names / prefixes to their upstream targets.
/// Auth headers are read from environment variables at resolution time
/// so they are never stored in the binary.

use std::env;

/// A resolved upstream target.
#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    /// Human-readable name (e.g. "openai", "anthropic", "ollama").
    pub name:    &'static str,
    /// HTTPS host (e.g. "api.openai.com").
    pub host:    &'static str,
    /// TCP port (443 for TLS upstreams).
    pub port:    u16,
    /// Base path prefix (e.g. "/v1").
    pub base:    &'static str,
    /// Whether this upstream uses TLS.
    pub tls:     bool,
    /// Whether this is an on-prem / local upstream (no data leaves the host).
    pub local:   bool,
    /// The environment variable name that holds the API key for this upstream.
    pub key_env: &'static str,
    /// The header name to send the key as (e.g. "Authorization" or "x-api-key").
    pub key_hdr: &'static str,
    /// Key prefix (e.g. "Bearer " for OpenAI, "" for Anthropic's x-api-key header).
    pub key_pfx: &'static str,
}

/// The static upstream table.  New upstreams are added here.
static UPSTREAMS: &[UpstreamTarget] = &[
    UpstreamTarget {
        name:    "openai",
        host:    "api.openai.com",
        port:    443,
        base:    "/v1",
        tls:     true,
        local:   false,
        key_env: "OPENAI_API_KEY",
        key_hdr: "Authorization",
        key_pfx: "Bearer ",
    },
    UpstreamTarget {
        name:    "anthropic",
        host:    "api.anthropic.com",
        port:    443,
        base:    "/v1",
        tls:     true,
        local:   false,
        key_env: "ANTHROPIC_API_KEY",
        key_hdr: "x-api-key",
        key_pfx: "",
    },
    UpstreamTarget {
        name:    "ollama",
        host:    "127.0.0.1",
        port:    11434,
        base:    "/api",
        tls:     false,
        local:   true,
        key_env: "",
        key_hdr: "",
        key_pfx: "",
    },
    UpstreamTarget {
        name:    "local",
        host:    "127.0.0.1",
        port:    8001,
        base:    "/v1",
        tls:     false,
        local:   true,
        key_env: "",
        key_hdr: "",
        key_pfx: "",
    },
];

// ── Model prefix → upstream mapping ──────────────────────────────────────────

/// (model_prefix, upstream_name) — first match wins, case-insensitive.
static MODEL_ROUTES: &[(&str, &str)] = &[
    ("gpt-",         "openai"),
    ("o1-",          "openai"),
    ("o3-",          "openai"),
    ("text-",        "openai"),
    ("claude-",      "anthropic"),
    ("llama",        "ollama"),
    ("mistral",      "ollama"),
    ("qwen",         "ollama"),
    ("gemma",        "ollama"),
    ("phi",          "ollama"),
    ("local/",       "local"),
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Resolve a model name to its upstream target.
///
/// Falls back to `"openai"` if no prefix matches (OpenAI-compatible default).
pub fn resolve_upstream(model: &str) -> &'static UpstreamTarget {
    let lower = model.to_lowercase();
    for (prefix, name) in MODEL_ROUTES {
        if lower.starts_with(prefix) {
            if let Some(t) = find_target(name) {
                return t;
            }
        }
    }
    // Default: OpenAI
    find_target("openai").expect("openai always present in UPSTREAMS")
}

/// Resolve a specific named upstream (e.g. for `RouteLocal` → "ollama").
pub fn resolve_named(name: &str) -> Option<&'static UpstreamTarget> {
    find_target(name)
}

/// Build the authentication headers for the given upstream.
/// Reads the API key from the environment variable specified in the target.
/// Returns an empty vec for local upstreams that need no auth.
pub fn build_auth_headers(target: &UpstreamTarget) -> Vec<(String, String)> {
    if target.key_env.is_empty() {
        return vec![];
    }
    let key = env::var(target.key_env).unwrap_or_default();
    if key.is_empty() {
        return vec![];
    }
    vec![(
        target.key_hdr.to_owned(),
        format!("{}{}", target.key_pfx, key),
    )]
}

/// Return all registered upstreams (for health-check enumeration).
pub fn all_upstreams() -> &'static [UpstreamTarget] {
    UPSTREAMS
}

fn find_target(name: &str) -> Option<&'static UpstreamTarget> {
    UPSTREAMS.iter().find(|t| t.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpt4_resolves_to_openai() {
        let t = resolve_upstream("gpt-4o");
        assert_eq!(t.name, "openai");
        assert_eq!(t.host, "api.openai.com");
        assert!(t.tls);
    }

    #[test]
    fn claude_resolves_to_anthropic() {
        let t = resolve_upstream("claude-3-opus");
        assert_eq!(t.name, "anthropic");
    }

    #[test]
    fn llama_resolves_to_ollama() {
        let t = resolve_upstream("llama3");
        assert_eq!(t.name, "ollama");
        assert!(!t.tls);
        assert!(t.local);
    }

    #[test]
    fn unknown_model_falls_back_to_openai() {
        let t = resolve_upstream("some-unknown-model");
        assert_eq!(t.name, "openai");
    }

    #[test]
    fn local_upstream_no_auth_headers() {
        let t = find_target("ollama").unwrap();
        let hdrs = build_auth_headers(t);
        assert!(hdrs.is_empty());
    }

    #[test]
    fn openai_auth_header_format() {
        // Set a dummy key for the test
        std::env::set_var("OPENAI_API_KEY", "sk-test-key");
        let t = find_target("openai").unwrap();
        let hdrs = build_auth_headers(t);
        assert_eq!(hdrs.len(), 1);
        assert_eq!(hdrs[0].0, "Authorization");
        assert_eq!(hdrs[0].1, "Bearer sk-test-key");
        std::env::remove_var("OPENAI_API_KEY");
    }
}
