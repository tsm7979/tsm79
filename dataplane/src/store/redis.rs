/// Redis-backed distributed state store.
///
/// Session pins:
///   Key:   tsm:session:{session_id}
///   Value: "local" | "cloud"
///   TTL:   4 hours (sliding)
///   Atomic pin upgrade via GETSET + Lua CAS script.
///
/// Rate limiting:
///   Sliding window log per IP using Redis ZSET.
///   Key:   tsm:rate:{ip}
///   Members: request timestamps (as score)
///   TTL:   60s (window size)
///   Implementation: ZADD + ZREMRANGEBYSCORE + ZCARD
///   Atomic via Lua script (single RTT per check).

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::route::RoutePin;
use super::DistributedState;

/// Bare-bones Redis client using raw TCP without any external crate.
/// The dataplane has a strict no-tokio / minimal-deps policy.
/// We speak the RESP2 wire protocol directly.
pub struct RedisStore {
    addr: String,
    password: Option<String>,
}

impl RedisStore {
    pub fn new(url: &str) -> Result<Self, String> {
        let (addr, password) = parse_redis_url(url)?;
        // Verify connectivity on construction
        let mut conn = TcpConn::connect(&addr, password.as_deref())
            .map_err(|e| format!("redis connect: {}", e))?;
        let pong = conn.cmd(&["PING"])?;
        if !pong.contains("PONG") {
            return Err(format!("redis PING failed: {}", pong));
        }
        Ok(RedisStore { addr, password })
    }

    fn conn(&self) -> Result<TcpConn, String> {
        TcpConn::connect(&self.addr, self.password.as_deref())
    }
}

impl DistributedState for RedisStore {
    fn session_pin(&self, session_id: &str, sensitive: bool) -> RoutePin {
        let key = format!("tsm:session:{}", session_id);
        let Ok(mut conn) = self.conn() else {
            // Redis down — fail open (conservative: treat as sensitive)
            return if sensitive { RoutePin::Local } else { RoutePin::Cloud };
        };

        let new_val = if sensitive { "local" } else { "cloud" };

        // Lua script: atomic CAS — sets to "local" if not set, or if upgrading cloud→local
        // KEYS[1]=key, ARGV[1]=new_val
        let script = r#"
local cur = redis.call('GET', KEYS[1])
if cur == false then
    redis.call('SET', KEYS[1], ARGV[1], 'EX', 14400)
    return ARGV[1]
elseif cur == 'cloud' and ARGV[1] == 'local' then
    redis.call('SET', KEYS[1], 'local', 'EX', 14400)
    return 'local'
else
    redis.call('EXPIRE', KEYS[1], 14400)
    return cur
end
"#;
        let result = conn.eval(script, &[&key], &[new_val])
            .unwrap_or_else(|_| new_val.to_owned());

        if result == "local" { RoutePin::Local } else { RoutePin::Cloud }
    }

    fn session_revoke(&self, session_id: &str) {
        let key = format!("tsm:session:{}", session_id);
        if let Ok(mut conn) = self.conn() {
            let _ = conn.cmd(&["DEL", &key]);
        }
    }

    fn rate_check(&self, ip: IpAddr, rpm: u32) -> bool {
        let key = format!("tsm:rate:{}", ip);
        let Ok(mut conn) = self.conn() else {
            return true; // Redis down — fail open
        };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let window_ms = 60_000u64;    // 1-minute sliding window
        let cutoff = now_ms.saturating_sub(window_ms);

        // Atomic sliding window via Lua:
        // 1. Remove timestamps older than the window
        // 2. Count remaining
        // 3. If count < limit → add current timestamp + return 1 (allowed)
        //    Else → return 0 (rate limited)
        let script = r#"
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = redis.call('ZCARD', key)
if count < limit then
    redis.call('ZADD', key, now, now)
    redis.call('PEXPIRE', key, 60000)
    return 1
else
    return 0
end
"#;
        let result = conn.eval(
            script,
            &[&key],
            &[&now_ms.to_string(), &cutoff.to_string(), &rpm.to_string()],
        ).unwrap_or_else(|_| "1".to_owned()); // fail open

        result.trim() == "1"
    }

    fn backend_name(&self) -> &'static str { "redis" }
}

// ── RESP2 TCP connection ──────────────────────────────────────────────────────

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

struct TcpConn {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl TcpConn {
    fn connect(addr: &str, password: Option<&str>) -> Result<Self, String> {
        let stream = TcpStream::connect(addr)
            .map_err(|e| e.to_string())?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| e.to_string())?;

        let reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        let mut conn = TcpConn { stream, reader };

        if let Some(pw) = password {
            conn.cmd(&["AUTH", pw])?;
        }
        Ok(conn)
    }

    /// Send a RESP2 inline command and read the simple reply.
    fn cmd(&mut self, args: &[&str]) -> Result<String, String> {
        // RESP2 array: *N\r\n$len\r\narg\r\n...
        let mut req = format!("*{}\r\n", args.len());
        for arg in args {
            req.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
        }
        self.stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        self.read_reply()
    }

    /// EVAL script NUMKEYS key [key…] arg [arg…]
    fn eval(&mut self, script: &str, keys: &[&str], args: &[&str]) -> Result<String, String> {
        let numkeys = keys.len().to_string();
        let mut all: Vec<&str> = vec!["EVAL", script, &numkeys];
        all.extend_from_slice(keys);
        all.extend_from_slice(args);
        self.cmd(&all)
    }

    fn read_reply(&mut self) -> Result<String, String> {
        let mut line = String::new();
        self.reader.read_line(&mut line).map_err(|e| e.to_string())?;
        let line = line.trim_end_matches("\r\n");
        match line.chars().next() {
            Some('+') => Ok(line[1..].to_owned()),
            Some('-') => Err(line[1..].to_owned()),
            Some(':') => Ok(line[1..].to_owned()),
            Some('$') => {
                let len: i64 = line[1..].parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
                if len < 0 { return Ok(String::new()); } // nil
                let mut bulk = vec![0u8; len as usize + 2]; // +2 for \r\n
                std::io::Read::read_exact(self.reader.get_mut(), &mut bulk)
                    .map_err(|e| e.to_string())?;
                Ok(String::from_utf8_lossy(&bulk[..len as usize]).into_owned())
            }
            Some('*') => {
                // Multi-bulk: return first element (sufficient for our scripts)
                let count: i64 = line[1..].parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
                let mut result = String::new();
                for i in 0..count {
                    let elem = self.read_reply()?;
                    if i == 0 { result = elem; }
                }
                Ok(result)
            }
            _ => Err(format!("unexpected RESP: {}", line)),
        }
    }
}

// ── URL parser ────────────────────────────────────────────────────────────────

fn parse_redis_url(url: &str) -> Result<(String, Option<String>), String> {
    // redis://:password@host:port/db  OR  redis://host:port
    let url = url.trim_start_matches("redis://");
    let (auth_part, host_part) = if url.contains('@') {
        let at = url.rfind('@').unwrap();
        (Some(&url[..at]), &url[at+1..])
    } else {
        (None, url)
    };

    // Strip /db suffix
    let host_port = host_part.split('/').next().unwrap_or(host_part);

    let password = auth_part.and_then(|a| {
        let pw = a.trim_start_matches(':');
        if pw.is_empty() { None } else { Some(pw.to_owned()) }
    });

    Ok((host_port.to_owned(), password))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_with_password() {
        let (addr, pw) = parse_redis_url("redis://:secret@127.0.0.1:6379/0").unwrap();
        assert_eq!(addr, "127.0.0.1:6379");
        assert_eq!(pw, Some("secret".to_owned()));
    }

    #[test]
    fn parse_url_no_password() {
        let (addr, pw) = parse_redis_url("redis://localhost:6379").unwrap();
        assert_eq!(addr, "localhost:6379");
        assert!(pw.is_none());
    }
}
