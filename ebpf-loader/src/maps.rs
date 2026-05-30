/// BPF map read/write helpers via bpf(2).
///
/// Provides typed wrappers for the map operations the control socket and
/// loader itself need: update, lookup, and delete for the specific key/value
/// types used by the TSM XDP maps.

use std::os::unix::io::RawFd;

pub use crate::bpf::BpfObj;

// ── BPF syscall constants ─────────────────────────────────────────────────────

const BPF_MAP_LOOKUP_ELEM: u64 = 1;
const BPF_MAP_UPDATE_ELEM: u64 = 2;
const BPF_MAP_DELETE_ELEM: u64 = 3;

#[repr(C)]
struct BpfMapOpAttr {
    map_fd:  u32,
    _pad0:   u32,
    key:     u64,   // pointer
    value:   u64,   // pointer (or next_key for GET_NEXT_KEY)
    flags:   u64,
}

const BPF_ANY:    u64 = 0;
const BPF_NOEXIST:u64 = 1;
const BPF_EXIST:  u64 = 2;

fn bpf_syscall(cmd: u64, attr: *const u8, size: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_bpf, cmd as libc::c_long, attr, size as libc::c_uint) as i64 }
}

fn bpf_map_attr(map_fd: RawFd, key: *const u8, val: *const u8, flags: u64) -> BpfMapOpAttr {
    BpfMapOpAttr {
        map_fd: map_fd as u32,
        _pad0:  0,
        key:    key as u64,
        value:  val as u64,
        flags,
    }
}

// ── Public operations ─────────────────────────────────────────────────────────

/// Update u32 key → u16 value (used for tsm_config[0] = port).
pub fn update_u32_u16(map_fd: RawFd, key: u32, val: u16) {
    let attr = bpf_map_attr(map_fd, &key as *const u32 as *const u8,
                            &val as *const u16 as *const u8, BPF_ANY);
    let rc = bpf_syscall(BPF_MAP_UPDATE_ELEM,
                          &attr as *const BpfMapOpAttr as *const u8,
                          std::mem::size_of::<BpfMapOpAttr>() as u32);
    if rc < 0 {
        eprintln!("[maps] update_u32_u16 failed: {}", std::io::Error::last_os_error());
    }
}

/// Block an IPv4 address: ip_blocked[addr] = 1.
pub fn block_ip(map_fd: RawFd, ipv4: u32) {
    let val: u8 = 1;
    let attr = bpf_map_attr(map_fd, &ipv4 as *const u32 as *const u8,
                            &val as *const u8, BPF_ANY);
    let rc = bpf_syscall(BPF_MAP_UPDATE_ELEM,
                          &attr as *const BpfMapOpAttr as *const u8,
                          std::mem::size_of::<BpfMapOpAttr>() as u32);
    if rc < 0 {
        eprintln!("[maps] block_ip({}) failed: {}", ipv4, std::io::Error::last_os_error());
    }
}

/// Unblock an IPv4 address: delete ip_blocked[addr].
pub fn unblock_ip(map_fd: RawFd, ipv4: u32) {
    let attr = BpfMapOpAttr {
        map_fd: map_fd as u32, _pad0: 0,
        key:    &ipv4 as *const u32 as u64,
        value:  0,
        flags:  0,
    };
    bpf_syscall(BPF_MAP_DELETE_ELEM,
                &attr as *const BpfMapOpAttr as *const u8,
                std::mem::size_of::<BpfMapOpAttr>() as u32);
}

/// Read tsm_stats[key] → u64.
pub fn read_stat(map_fd: RawFd, key: u32) -> u64 {
    let mut val: u64 = 0;
    let attr = bpf_map_attr(map_fd, &key as *const u32 as *const u8,
                            &mut val as *mut u64 as *const u8, BPF_ANY);
    let rc = bpf_syscall(BPF_MAP_LOOKUP_ELEM,
                          &attr as *const BpfMapOpAttr as *const u8,
                          std::mem::size_of::<BpfMapOpAttr>() as u32);
    if rc < 0 { 0 } else { val }
}

/// Read ip_request_count[addr] for a single IPv4 (sums all per-CPU buckets).
/// Returns 0 if not found.
pub fn read_ip_count(map_fd: RawFd, ipv4: u32, num_cpus: usize) -> u64 {
    // PERCPU_HASH returns one value per CPU as a contiguous array
    let mut vals = vec![0u64; num_cpus.max(1)];
    let attr = bpf_map_attr(map_fd, &ipv4 as *const u32 as *const u8,
                            vals.as_mut_ptr() as *const u8, BPF_ANY);
    let rc = bpf_syscall(BPF_MAP_LOOKUP_ELEM,
                          &attr as *const BpfMapOpAttr as *const u8,
                          std::mem::size_of::<BpfMapOpAttr>() as u32);
    if rc < 0 { 0 } else { vals.iter().sum() }
}

/// Detect the number of online CPUs for PERCPU map reads.
pub fn num_possible_cpus() -> usize {
    // Read /sys/devices/system/cpu/possible
    if let Ok(s) = std::fs::read_to_string("/sys/devices/system/cpu/possible") {
        // Format: "0-N" or "0,1,2" — parse last number + 1
        let s = s.trim();
        if let Some(dash) = s.rfind('-') {
            if let Ok(n) = s[dash+1..].parse::<usize>() {
                return n + 1;
            }
        }
    }
    // Fallback: use libc sysconf
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n > 0 { n as usize } else { 1 }
}

/// Decode a dotted-quad IPv4 string to a u32 in network byte order.
pub fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    let a = parts[0].parse::<u8>().ok()?;
    let b = parts[1].parse::<u8>().ok()?;
    let c = parts[2].parse::<u8>().ok()?;
    let d = parts[3].parse::<u8>().ok()?;
    // Network byte order = big-endian
    Some(u32::from_be_bytes([a, b, c, d]))
}

/// Format a u32 network-byte-order IPv4 as dotted-quad.
pub fn format_ipv4(addr: u32) -> String {
    let [a, b, c, d] = addr.to_be_bytes();
    format!("{}.{}.{}.{}", a, b, c, d)
}

// ── MapOp (used by control socket) ───────────────────────────────────────────

pub enum MapOp {
    Block(u32),       // ipv4 network-byte-order
    Unblock(u32),
    Stats,
    Count(u32),
}

pub fn execute_op(obj: &BpfObj, op: MapOp) -> String {
    let ncpu = num_possible_cpus();
    match op {
        MapOp::Block(ip) => {
            if let Some(fd) = obj.map_fd("ip_blocked") {
                block_ip(fd, ip);
                format!("OK blocked {}", format_ipv4(ip))
            } else {
                "ERROR ip_blocked map not found".to_owned()
            }
        }
        MapOp::Unblock(ip) => {
            if let Some(fd) = obj.map_fd("ip_blocked") {
                unblock_ip(fd, ip);
                format!("OK unblocked {}", format_ipv4(ip))
            } else {
                "ERROR ip_blocked map not found".to_owned()
            }
        }
        MapOp::Stats => {
            let fd = obj.map_fd("tsm_stats").unwrap_or(-1);
            let total   = if fd >= 0 { read_stat(fd, 0) } else { 0 };
            let dropped = if fd >= 0 { read_stat(fd, 1) } else { 0 };
            let passed  = if fd >= 0 { read_stat(fd, 2) } else { 0 };
            format!("total={} dropped={} passed={}", total, dropped, passed)
        }
        MapOp::Count(ip) => {
            if let Some(fd) = obj.map_fd("ip_request_count") {
                let cnt = read_ip_count(fd, ip, ncpu);
                format!("count={} ip={}", cnt, format_ipv4(ip))
            } else {
                "ERROR ip_request_count map not found".to_owned()
            }
        }
    }
}
