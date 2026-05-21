/// tsm-ctl — The Sovereign Mechanica CLI
///
/// A synchronous command-line interface to the TSM Admin API and Dataplane.
/// Uses ureq (no async runtime) for minimal binary size and fast startup.
///
/// Configuration (precedence: flag > env var > ~/.tsm/config.json):
///   --server  TSM_SERVER   Admin API base URL  (default: http://localhost:9090)
///   --token   TSM_TOKEN    Bearer access token
///
/// Commands:
///   auth login              — obtain and cache access + refresh tokens
///   auth refresh            — refresh the cached access token
///   auth logout             — revoke cached refresh token
///
///   policy get [WORKSPACE]  — print current policy rules
///   policy set  WORKSPACE FILE — upload rules from JSON file
///
///   audit query [FLAGS]     — query audit log (paginated)
///   audit summary           — 24h KPI summary
///
///   workspace list          — list workspaces
///   workspace create SLUG   — create a new workspace
///   workspace delete ID     — archive a workspace
///
///   node list               — list cluster nodes
///   node drain ID           — drain a node (mark unhealthy)
///
///   health                  — check dataplane /health, admin API /actuator/health, and threat-intel /health
///
///   xdp list                — list all XDP-blocked IPs (via threat-intel)
///   xdp block IP            — add IP to kernel XDP blocklist
///   xdp unblock IP          — remove IP from XDP blocklist
///   xdp lookup IP           — look up IP threat-intel reputation
///   xdp tor IP              — check if IP is a Tor exit node
///   xdp size                — show total blocked IP count
///
///   intel feeds             — show status of all feed pollers (NVD, AbuseIPDB, OTX, …)
///   intel tor               — show Tor exit node count
///   intel blocklist         — show XDP blocklist size

use std::collections::HashMap;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use colored::Colorize;
use comfy_table::{Table, presets::UTF8_FULL};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "tsm-ctl",
    version = "1.0.0",
    about = "TSM — The Sovereign Mechanica CLI",
    long_about = None,
)]
struct Cli {
    /// Admin API base URL
    #[arg(long, env = "TSM_SERVER", default_value = "http://localhost:9090", global = true)]
    server: String,

    /// Bearer token (overrides cached token)
    #[arg(long, env = "TSM_TOKEN", global = true)]
    token: Option<String>,

    /// Output format: table | json
    #[arg(long, default_value = "table", global = true)]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Authentication: login, refresh, logout
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },

    /// Policy management
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// Audit log query
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Workspace management
    Workspace {
        #[command(subcommand)]
        action: WorkspaceCommands,
    },

    /// Cluster node management
    Node {
        #[command(subcommand)]
        action: NodeCommands,
    },

    /// XDP kernel blocklist management (talks to threat-intel service)
    Xdp {
        #[command(subcommand)]
        action: XdpCommands,
        /// Threat-intel service URL
        #[arg(long, env = "TSM_INTEL_URL", default_value = "http://localhost:9100", global = true)]
        intel_url: String,
    },

    /// Threat intelligence feed status
    Intel {
        #[command(subcommand)]
        action: IntelCommands,
        /// Threat-intel service URL
        #[arg(long, env = "TSM_INTEL_URL", default_value = "http://localhost:9100", global = true)]
        intel_url: String,
    },

    /// Check service health
    Health {
        /// Dataplane address
        #[arg(long, env = "TSM_DATAPLANE", default_value = "http://localhost:8080")]
        dataplane: String,
        /// Threat-intel service URL (optional)
        #[arg(long, env = "TSM_INTEL_URL", default_value = "http://localhost:9100")]
        intel_url: String,
    },
}

#[derive(Subcommand)]
enum XdpCommands {
    /// List all blocked IPs in the XDP kernel blocklist
    List,
    /// Add an IP to the XDP blocklist (dropped at NIC level)
    Block {
        ip: String,
        #[arg(long, default_value = "manual")]
        reason: String,
        #[arg(long, default_value_t = 24, help = "TTL in hours")]
        ttl_hours: u32,
    },
    /// Remove an IP from the XDP blocklist
    Unblock { ip: String },
    /// Look up IP reputation from threat intel feeds
    Lookup { ip: String },
    /// Check if an IP is a known Tor exit node
    Tor { ip: String },
    /// Show XDP blocklist size
    Size,
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Login with email/password and cache tokens
    Login {
        #[arg(long, env = "TSM_EMAIL")]
        email: String,
        #[arg(long, env = "TSM_PASSWORD")]
        password: String,
    },
    /// Refresh the cached access token
    Refresh,
    /// Revoke the cached refresh token
    Logout,
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Get current policy for a workspace
    Get {
        #[arg(default_value = "00000000-0000-0000-0000-000000000002")]
        workspace_id: String,
    },
    /// Upload policy rules from a JSON file
    Set {
        workspace_id: String,
        /// Path to rules JSON file (array of rule objects)
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Query the audit log
    Query {
        #[arg(long)]          workspace_id: Option<String>,
        #[arg(long)]          from: Option<String>,
        #[arg(long)]          to: Option<String>,
        #[arg(long)]          action: Option<String>,
        #[arg(long)]          min_risk: Option<f64>,
        #[arg(long, default_value = "0")]  page: u32,
        #[arg(long, default_value = "20")] size: u32,
    },
    /// Show 24h KPI summary
    Summary {
        #[arg(long)] workspace_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum WorkspaceCommands {
    /// List all workspaces
    List,
    /// Create a new workspace
    Create {
        slug: String,
        #[arg(long, default_value = "")]
        display_name: String,
        #[arg(long, default_value_t = 1000)]
        rate_limit_rpm: u32,
    },
    /// Archive a workspace
    Delete { id: String },
}

#[derive(Subcommand)]
enum NodeCommands {
    /// List cluster nodes
    List,
    /// Drain a node (mark unhealthy, removes from LB)
    Drain { id: String },
}

#[derive(Subcommand)]
enum IntelCommands {
    /// Show status of all threat-intel feed pollers
    Feeds,
    /// Show Tor exit node count
    Tor,
    /// Show blocklist size
    Blocklist,
}

// ── Token cache ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
struct TokenCache {
    access_token:  Option<String>,
    refresh_token: Option<String>,
}

fn cache_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_owned());
    PathBuf::from(home).join(".tsm").join("tokens.json")
}

fn load_cache() -> TokenCache {
    let path = cache_path();
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_cache(cache: &TokenCache) {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(cache) {
        let _ = std::fs::write(&path, json);
        // Restrict permissions: chmod 600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

// ── HTTP client helpers ────────────────────────────────────────────────────────

struct Client {
    base:  String,
    token: Option<String>,
}

impl Client {
    fn new(base: &str, token: Option<String>) -> Self {
        Client { base: base.trim_end_matches('/').to_owned(), token }
    }

    fn get(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base, path);
        let mut req = ureq::get(&url);
        if let Some(t) = &self.token {
            req = req.set("Authorization", &format!("Bearer {}", t));
        }
        req.call()
            .map_err(|e| format!("GET {}: {}", url, e))?
            .into_json::<Value>()
            .map_err(|e| format!("JSON decode: {}", e))
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base, path);
        let mut req = ureq::post(&url);
        if let Some(t) = &self.token {
            req = req.set("Authorization", &format!("Bearer {}", t));
        }
        req.send_json(body)
            .map_err(|e| format!("POST {}: {}", url, e))?
            .into_json::<Value>()
            .map_err(|e| format!("JSON decode: {}", e))
    }

    fn delete(&self, path: &str) -> Result<(), String> {
        let url = format!("{}{}", self.base, path);
        let mut req = ureq::delete(&url);
        if let Some(t) = &self.token {
            req = req.set("Authorization", &format!("Bearer {}", t));
        }
        req.call().map_err(|e| format!("DELETE {}: {}", url, e))?;
        Ok(())
    }
}

// ── Output helpers ─────────────────────────────────────────────────────────────

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn kv_table(pairs: &[(&str, String)]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Key", "Value"]);
    for (k, v) in pairs {
        table.add_row(vec![k.bold().to_string(), v.clone()]);
    }
    println!("{table}");
}

fn rows_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(headers.iter().map(|h| h.bold().to_string()).collect::<Vec<_>>());
    for row in rows {
        table.add_row(row);
    }
    println!("{table}");
}

fn ok(msg: &str)  { println!("{} {}", "✓".green().bold(), msg); }
fn err(msg: &str) { eprintln!("{} {}", "✗".red().bold(), msg); std::process::exit(1); }

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // Resolve bearer token: flag > env > cache
    let token = cli.token.clone().or_else(|| load_cache().access_token);
    let client = Client::new(&cli.server, token);

    match cli.command {
        Commands::Auth { action } => handle_auth(action, &cli.server),
        Commands::Policy { action } => handle_policy(action, &client, &cli.output),
        Commands::Audit { action } => handle_audit(action, &client, &cli.output),
        Commands::Workspace { action } => handle_workspace(action, &client, &cli.output),
        Commands::Node { action } => handle_node(action, &client, &cli.output),
        Commands::Xdp { action, intel_url } => handle_xdp(action, &intel_url, &cli.output),
        Commands::Intel { action, intel_url } => handle_intel(action, &intel_url, &cli.output),
        Commands::Health { dataplane, intel_url } => handle_health(&cli.server, &dataplane, &intel_url),
    }
}

// ── XDP blocklist ──────────────────────────────────────────────────────────────

fn handle_xdp(action: XdpCommands, intel_url: &str, output: &OutputFormat) {
    let client = Client::new(intel_url, None);
    match action {
        XdpCommands::List => {
            match client.get("/intel/blocklist") {
                Ok(v) => {
                    match output {
                        OutputFormat::Json => print_json(&v),
                        OutputFormat::Table => {
                            let empty = vec![];
                            let entries = v.as_array().unwrap_or(&empty);
                            if entries.is_empty() {
                                println!("Blocklist is empty.");
                                return;
                            }
                            let rows: Vec<Vec<String>> = entries.iter().map(|e| vec![
                                e["ip"].as_str().unwrap_or("").to_owned(),
                                e["reason"].as_str().unwrap_or("").to_owned(),
                                e["added_at"].as_str().unwrap_or("").to_owned(),
                                e["expires_at"].as_str().unwrap_or("never").to_owned(),
                            ]).collect();
                            rows_table(&["IP", "Reason", "Added At", "Expires At"], &rows);
                        }
                    }
                }
                Err(e) => err(&format!("Blocklist fetch failed: {}", e)),
            }
        }

        XdpCommands::Block { ip, reason, ttl_hours } => {
            let body = serde_json::json!({
                "ip":        ip,
                "reason":    reason,
                "ttl_hours": ttl_hours,
            });
            match client.post("/intel/block", &body) {
                Ok(_) => ok(&format!("IP {} added to XDP blocklist (TTL: {}h, reason: {})", ip, ttl_hours, reason)),
                Err(e) => err(&format!("Block failed: {}", e)),
            }
        }

        XdpCommands::Unblock { ip } => {
            let body = serde_json::json!({ "ip": ip });
            match client.post("/intel/unblock", &body) {
                Ok(_) => ok(&format!("IP {} removed from XDP blocklist", ip)),
                Err(e) => err(&format!("Unblock failed: {}", e)),
            }
        }

        XdpCommands::Lookup { ip } => {
            match client.get(&format!("/intel/ip/{}", ip)) {
                Ok(v) => {
                    match output {
                        OutputFormat::Json => print_json(&v),
                        OutputFormat::Table => {
                            kv_table(&[
                                ("IP",            v["ip"].as_str().unwrap_or(&ip).to_owned()),
                                ("Score",         v["score"].as_f64().map(|s| format!("{:.3}", s)).unwrap_or_default()),
                                ("Categories",    v["categories"].as_str().unwrap_or("").to_owned()),
                                ("Source",        v["source"].as_str().unwrap_or("").to_owned()),
                                ("Last Updated",  v["last_updated"].as_str().unwrap_or("").to_owned()),
                                ("Country",       v["country_code"].as_str().unwrap_or("?").to_owned()),
                                ("Is Tor",        v["is_tor"].as_bool().map(|b| b.to_string()).unwrap_or("false".to_owned())),
                                ("Is VPN",        v["is_vpn"].as_bool().map(|b| b.to_string()).unwrap_or("false".to_owned())),
                            ]);
                        }
                    }
                }
                Err(e) => {
                    if e.contains("404") || e.contains("unknown") {
                        println!("IP {} is not in the threat intel database (clean or unscanned).", ip);
                    } else {
                        err(&format!("Lookup failed: {}", e));
                    }
                }
            }
        }

        XdpCommands::Tor { ip } => {
            match client.get(&format!("/intel/tor/{}", ip)) {
                Ok(v) => {
                    let is_tor = v["is_tor"].as_bool().unwrap_or(false);
                    if is_tor {
                        println!("{} {} is a known Tor exit node.", "⚠".yellow().bold(), ip);
                    } else {
                        println!("{} {} is NOT a Tor exit node.", "✓".green().bold(), ip);
                    }
                }
                Err(e) => err(&format!("Tor check failed: {}", e)),
            }
        }

        XdpCommands::Size => {
            match client.get("/intel/blocklist/size") {
                Ok(v) => {
                    let size = v["size"].as_i64().unwrap_or(0);
                    println!("XDP blocklist: {} IPs", size.to_string().yellow().bold());
                }
                Err(e) => err(&format!("Size fetch failed: {}", e)),
            }
        }
    }
}

// ── Threat intelligence feeds ──────────────────────────────────────────────────

fn handle_intel(action: IntelCommands, intel_url: &str, output: &OutputFormat) {
    let client = Client::new(intel_url, None);
    match action {
        IntelCommands::Feeds => {
            match client.get("/feeds/stats") {
                Ok(v) => {
                    match output {
                        OutputFormat::Json => print_json(&v),
                        OutputFormat::Table => {
                            let empty = vec![];
                            let stats = v.as_array().unwrap_or(&empty);
                            if stats.is_empty() {
                                println!("No feed stats available yet.");
                                return;
                            }
                            let rows: Vec<Vec<String>> = stats.iter().map(|s| {
                                let ok = s["error_count"].as_i64().unwrap_or(0) == 0;
                                vec![
                                    s["feed_name"].as_str().unwrap_or("").to_owned(),
                                    s["record_count"].as_i64().map(|n| n.to_string()).unwrap_or_default(),
                                    s["last_poll_at"].as_str().unwrap_or("never").to_owned(),
                                    if ok { "OK".green().to_string() } else { format!("ERR: {}", s["last_error_msg"].as_str().unwrap_or("?")).red().to_string() },
                                ]
                            }).collect();
                            rows_table(&["Feed", "Records", "Last Poll", "Status"], &rows);
                        }
                    }
                }
                Err(e) => err(&format!("Feed stats failed: {}", e)),
            }
        }

        IntelCommands::Tor => {
            match client.get("/health") {
                Ok(v) => {
                    let n = v["tor_nodes"].as_i64().unwrap_or(0);
                    println!("Known Tor exit nodes: {}", n.to_string().yellow().bold());
                }
                Err(e) => err(&format!("Health check failed: {}", e)),
            }
        }

        IntelCommands::Blocklist => {
            match client.get("/intel/blocklist/size") {
                Ok(v) => {
                    let size = v["size"].as_i64().unwrap_or(0);
                    println!("XDP blocklist size: {} IPs", size.to_string().yellow().bold());
                }
                Err(e) => err(&format!("Blocklist size failed: {}", e)),
            }
        }
    }
}

// ── Auth ───────────────────────────────────────────────────────────────────────

fn handle_auth(action: AuthCommands, server: &str) {
    let client = Client::new(server, None);
    match action {
        AuthCommands::Login { email, password } => {
            let body = serde_json::json!({ "email": email, "password": password });
            match client.post("/api/auth/login", &body) {
                Ok(v) => {
                    let access  = v["accessToken"].as_str().unwrap_or("").to_owned();
                    let refresh = v["refreshToken"].as_str().unwrap_or("").to_owned();
                    save_cache(&TokenCache {
                        access_token:  Some(access.clone()),
                        refresh_token: Some(refresh),
                    });
                    ok(&format!("Logged in. Access token cached at {}", cache_path().display()));
                    println!("  expires_in: {}s", v["expiresIn"].as_str().unwrap_or("?"));
                }
                Err(e) => err(&format!("Login failed: {}", e)),
            }
        }

        AuthCommands::Refresh => {
            let cache = load_cache();
            let rt = cache.refresh_token.as_deref().unwrap_or("");
            if rt.is_empty() {
                err("No cached refresh token. Run: tsm-ctl auth login");
            }
            let body = serde_json::json!({ "refreshToken": rt });
            match client.post("/api/auth/refresh", &body) {
                Ok(v) => {
                    let access = v["accessToken"].as_str().unwrap_or("").to_owned();
                    save_cache(&TokenCache {
                        access_token:  Some(access),
                        refresh_token: cache.refresh_token,
                    });
                    ok("Access token refreshed and cached");
                }
                Err(e) => err(&format!("Refresh failed: {}", e)),
            }
        }

        AuthCommands::Logout => {
            let cache = load_cache();
            let rt = cache.refresh_token.as_deref().unwrap_or("").to_owned();
            if !rt.is_empty() {
                let body = serde_json::json!({ "refreshToken": rt });
                let _ = client.post("/api/auth/logout", &body);
            }
            save_cache(&TokenCache::default());
            ok("Logged out. Token cache cleared.");
        }
    }
}

// ── Policy ────────────────────────────────────────────────────────────────────

fn handle_policy(action: PolicyCommands, client: &Client, fmt: &OutputFormat) {
    match action {
        PolicyCommands::Get { workspace_id } => {
            let path = format!("/api/policy/{}/current", workspace_id);
            match client.get(&path) {
                Ok(v) => {
                    match fmt {
                        OutputFormat::Json => print_json(&v),
                        OutputFormat::Table => {
                            let version = v["version"].as_i64().unwrap_or(0);
                            println!("{} Policy v{} for workspace {}", "→".cyan(), version, workspace_id);
                            if let Some(rules) = v["rulesJson"].as_str()
                                .and_then(|s| serde_json::from_str::<Vec<Value>>(s).ok())
                            {
                                let rows: Vec<Vec<String>> = rules.iter().map(|r| vec![
                                    r["name"].as_str().unwrap_or("?").to_owned(),
                                    r["action"].as_str().unwrap_or("?").to_owned(),
                                    r["priority"].as_i64().map(|n| n.to_string()).unwrap_or_default(),
                                    r["enabled"].as_bool().map(|b| if b { "yes" } else { "no" }).unwrap_or("?").to_owned(),
                                ]).collect();
                                rows_table(&["Name", "Action", "Priority", "Enabled"], &rows);
                            } else {
                                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                            }
                        }
                    }
                }
                Err(e) => err(&format!("Failed to get policy: {}", e)),
            }
        }

        PolicyCommands::Set { workspace_id, file } => {
            let content = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| { err(&format!("Cannot read {}: {}", file.display(), e)); unreachable!() });
            let rules_json: Value = serde_json::from_str(&content)
                .unwrap_or_else(|e| { err(&format!("Invalid JSON: {}", e)); unreachable!() });
            let body = serde_json::json!({ "rulesJson": rules_json.to_string() });
            let path = format!("/api/policy/{}/snapshots", workspace_id);
            match client.post(&path, &body) {
                Ok(v) => {
                    ok(&format!("Policy snapshot created: version {}", v["version"]));
                }
                Err(e) => err(&format!("Failed to set policy: {}", e)),
            }
        }
    }
}

// ── Audit ─────────────────────────────────────────────────────────────────────

fn handle_audit(action: AuditCommands, client: &Client, fmt: &OutputFormat) {
    match action {
        AuditCommands::Query { workspace_id, from, to, action: act, min_risk, page, size } => {
            let mut params = format!("?page={}&size={}", page, size);
            if let Some(ws) = workspace_id { params += &format!("&workspaceId={}", ws); }
            if let Some(f) = from           { params += &format!("&from={}", f); }
            if let Some(t) = to             { params += &format!("&to={}", t); }
            if let Some(a) = act            { params += &format!("&action={}", a); }
            if let Some(r) = min_risk       { params += &format!("&minRisk={}", r); }

            match client.get(&format!("/api/audit{}", params)) {
                Ok(v) => {
                    match fmt {
                        OutputFormat::Json => print_json(&v),
                        OutputFormat::Table => {
                            println!("  Total: {} | Page {}/{}", v["total"], v["page"], v["totalPages"]);
                            if let Some(data) = v["data"].as_array() {
                                let rows: Vec<Vec<String>> = data.iter().map(|e| vec![
                                    e["ts"].as_str().unwrap_or("?").chars().take(19).collect(),
                                    e["action"].as_str().unwrap_or("?").to_owned(),
                                    e["model"].as_str().unwrap_or("").to_owned(),
                                    e["clientIp"].as_str().unwrap_or("").to_owned(),
                                    e["riskScore"].as_f64().map(|f| format!("{:.0}", f)).unwrap_or_default(),
                                    e["ruleFired"].as_str().unwrap_or("").to_owned(),
                                ]).collect();
                                rows_table(&["Time", "Action", "Model", "Client IP", "Risk", "Rule"], &rows);
                            }
                        }
                    }
                }
                Err(e) => err(&format!("Audit query failed: {}", e)),
            }
        }

        AuditCommands::Summary { workspace_id } => {
            let params = workspace_id.map(|id| format!("?workspaceId={}", id)).unwrap_or_default();
            match client.get(&format!("/api/audit/summary{}", params)) {
                Ok(v) => {
                    match fmt {
                        OutputFormat::Json => print_json(&v),
                        OutputFormat::Table => {
                            kv_table(&[
                                ("Window",    format!("{}h", v["windowHours"])),
                                ("Total",     v["total"].to_string()),
                                ("Blocked",   v["blocked"].to_string()),
                                ("Block rate",format!("{}%", v["blockRatePct"])),
                            ]);
                        }
                    }
                }
                Err(e) => err(&format!("Audit summary failed: {}", e)),
            }
        }
    }
}

// ── Workspace ─────────────────────────────────────────────────────────────────

fn handle_workspace(action: WorkspaceCommands, client: &Client, fmt: &OutputFormat) {
    match action {
        WorkspaceCommands::List => {
            match client.get("/api/workspaces") {
                Ok(v) => {
                    match fmt {
                        OutputFormat::Json => print_json(&v),
                        OutputFormat::Table => {
                            if let Some(ws) = v.as_array() {
                                let rows: Vec<Vec<String>> = ws.iter().map(|w| vec![
                                    w["id"].as_str().unwrap_or("").to_owned(),
                                    w["slug"].as_str().unwrap_or("").to_owned(),
                                    w["displayName"].as_str().unwrap_or("").to_owned(),
                                    w["rateLimitRpm"].as_i64().map(|n| n.to_string()).unwrap_or_default(),
                                    if w["archivedAt"].is_null() { "active".green().to_string() } else { "archived".red().to_string() },
                                ]).collect();
                                rows_table(&["ID", "Slug", "Name", "RPM Limit", "Status"], &rows);
                            }
                        }
                    }
                }
                Err(e) => err(&format!("List workspaces failed: {}", e)),
            }
        }

        WorkspaceCommands::Create { slug, display_name, rate_limit_rpm } => {
            let dn = if display_name.is_empty() { slug.clone() } else { display_name };
            let body = serde_json::json!({
                "slug": slug, "displayName": dn, "rateLimitRpm": rate_limit_rpm
            });
            match client.post("/api/workspaces", &body) {
                Ok(v) => ok(&format!("Created workspace: {} ({})", v["slug"], v["id"])),
                Err(e) => err(&format!("Create workspace failed: {}", e)),
            }
        }

        WorkspaceCommands::Delete { id } => {
            match client.delete(&format!("/api/workspaces/{}", id)) {
                Ok(()) => ok(&format!("Workspace {} archived", id)),
                Err(e) => err(&format!("Delete workspace failed: {}", e)),
            }
        }
    }
}

// ── Nodes ─────────────────────────────────────────────────────────────────────

fn handle_node(action: NodeCommands, client: &Client, fmt: &OutputFormat) {
    match action {
        NodeCommands::List => {
            match client.get("/api/nodes") {
                Ok(v) => {
                    match fmt {
                        OutputFormat::Json => print_json(&v),
                        OutputFormat::Table => {
                            if let Some(nodes) = v.as_array() {
                                let rows: Vec<Vec<String>> = nodes.iter().map(|n| {
                                    let healthy = n["healthy"].as_bool().unwrap_or(false);
                                    vec![
                                        n["id"].as_str().unwrap_or("").to_owned(),
                                        n["role"].as_str().unwrap_or("").to_owned(),
                                        n["addr"].as_str().unwrap_or("").to_owned(),
                                        n["region"].as_str().unwrap_or("").to_owned(),
                                        if healthy { "healthy".green().to_string() } else { "unhealthy".red().to_string() },
                                        n["secondsSinceSeen"].as_i64().map(|s| format!("{}s ago", s)).unwrap_or_default(),
                                        n["policyVersion"].as_i64().map(|v| format!("v{}", v)).unwrap_or_default(),
                                    ]
                                }).collect();
                                rows_table(&["ID", "Role", "Addr", "Region", "Status", "Last Seen", "Policy"], &rows);
                            }
                        }
                    }
                }
                Err(e) => err(&format!("List nodes failed: {}", e)),
            }
        }

        NodeCommands::Drain { id } => {
            let body = serde_json::json!({});
            match client.post(&format!("/api/nodes/{}/drain", id), &body) {
                Ok(v) => ok(&format!("Node {} drained: {}", id, v["status"])),
                Err(e) => err(&format!("Drain failed: {}", e)),
            }
        }
    }
}

// ── Health ────────────────────────────────────────────────────────────────────

fn handle_health(admin_server: &str, dataplane: &str, intel_url: &str) {
    // Check admin API
    let admin_client = Client::new(admin_server, None);
    match admin_client.get("/actuator/health") {
        Ok(v) => {
            let status = v["status"].as_str().unwrap_or("?");
            if status == "UP" {
                ok(&format!("Admin API: {}", status));
            } else {
                eprintln!("{} Admin API: {}", "!".yellow().bold(), status);
            }
        }
        Err(e) => eprintln!("{} Admin API unreachable: {}", "✗".red(), e),
    }

    // Check dataplane
    let dp_client = Client::new(dataplane, None);
    match dp_client.get("/health") {
        Ok(v) => ok(&format!("Dataplane: {}", v["status"].as_str().unwrap_or("ok"))),
        Err(e) => eprintln!("{} Dataplane unreachable: {}", "✗".red(), e),
    }

    // Check threat-intel service
    let intel_client = Client::new(intel_url, None);
    match intel_client.get("/health") {
        Ok(v) => {
            let status    = v["status"].as_str().unwrap_or("?");
            let redis_ok  = v["redis"].as_bool().unwrap_or(false);
            let tor_nodes = v["tor_nodes"].as_i64().unwrap_or(0);
            let blocked   = v["blocked_ips"].as_i64().unwrap_or(0);
            if status == "ok" && redis_ok {
                ok(&format!(
                    "Threat Intel: {} (tor_nodes: {}, xdp_blocked: {})",
                    status, tor_nodes, blocked
                ));
            } else {
                eprintln!(
                    "{} Threat Intel: {} (redis: {})",
                    "!".yellow().bold(), status, redis_ok
                );
            }
        }
        Err(e) => eprintln!("{} Threat Intel unreachable: {}", "✗".red(), e),
    }
}
