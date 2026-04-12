/// Unix-domain control socket for the eBPF loader.
///
/// The data plane connects to this socket to perform BPF map operations:
///
///   BLOCK <ip>       → add ip to ip_blocked map
///   UNBLOCK <ip>     → remove ip from ip_blocked map
///   STATS            → read tsm_stats counters (total/dropped/passed)
///   COUNT <ip>       → read ip_request_count for one IP
///
/// Protocol: newline-delimited text (one command per line, one response per line).
/// Each response ends with "\n".  The connection is closed after each command
/// (simplest possible protocol — no persistent sessions needed).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

use crate::bpf::BpfObj;
use crate::maps::{self, MapOp, parse_ipv4};

/// Start the control socket loop (blocks the calling thread).
pub fn run_control_socket(path: &str, obj: &BpfObj) {
    // Remove stale socket if it exists
    if Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }

    // Create parent directory if needed
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = match UnixListener::bind(path) {
        Ok(l)  => l,
        Err(e) => {
            eprintln!("[socket] failed to bind {}: {}", path, e);
            eprintln!("[socket] control socket unavailable — continuing without it");
            // Block forever — the process is alive for XDP, even without the socket
            loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
        }
    };

    eprintln!("[socket] listening on {}", path);

    // Wrap BpfObj in Arc so it can be shared across client threads
    // BpfObj is not Clone, so we use a Mutex for shared access
    use std::sync::Mutex;
    let obj_shared = Arc::new(Mutex::new(obj as *const BpfObj as usize));

    for stream in listener.incoming() {
        match stream {
            Ok(mut conn) => {
                let obj_ptr_val = Arc::clone(&obj_shared);
                std::thread::spawn(move || {
                    let obj_ptr = *obj_ptr_val.lock().unwrap() as *const BpfObj;
                    // SAFETY: obj lives for the process lifetime (allocated in main)
                    let obj_ref: &BpfObj = unsafe { &*obj_ptr };
                    handle_client(&mut conn, obj_ref);
                });
            }
            Err(e) => eprintln!("[socket] accept error: {}", e),
        }
    }
}

fn handle_client(conn: &mut std::os::unix::net::UnixStream, obj: &BpfObj) {
    let reader    = BufReader::new(conn.try_clone().expect("clone stream"));
    let mut lines = reader.lines();

    while let Some(Ok(line)) = lines.next() {
        let line = line.trim().to_owned();
        if line.is_empty() { continue; }

        let response = dispatch(&line, obj);
        let out = format!("{}\n", response);
        let _ = conn.write_all(out.as_bytes());
    }
}

fn dispatch(cmd: &str, obj: &BpfObj) -> String {
    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    match parts[0].to_uppercase().as_str() {
        "BLOCK" => {
            if parts.len() < 2 { return "ERROR missing IP argument".to_owned(); }
            match parse_ipv4(parts[1].trim()) {
                Some(ip) => maps::execute_op(obj, MapOp::Block(ip)),
                None     => format!("ERROR invalid IP: {}", parts[1]),
            }
        }
        "UNBLOCK" => {
            if parts.len() < 2 { return "ERROR missing IP argument".to_owned(); }
            match parse_ipv4(parts[1].trim()) {
                Some(ip) => maps::execute_op(obj, MapOp::Unblock(ip)),
                None     => format!("ERROR invalid IP: {}", parts[1]),
            }
        }
        "STATS" => maps::execute_op(obj, MapOp::Stats),
        "COUNT" => {
            if parts.len() < 2 { return "ERROR missing IP argument".to_owned(); }
            match parse_ipv4(parts[1].trim()) {
                Some(ip) => maps::execute_op(obj, MapOp::Count(ip)),
                None     => format!("ERROR invalid IP: {}", parts[1]),
            }
        }
        "PING" => "PONG".to_owned(),
        "QUIT" | "EXIT" => "BYE".to_owned(),
        other => format!("ERROR unknown command: {}", other),
    }
}
