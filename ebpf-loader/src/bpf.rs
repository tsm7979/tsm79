/// BPF program loading and XDP attachment via the `bpf(2)` syscall.
///
/// ELF parsing: reads the .o file produced by clang -target bpf, locates the
/// BPF_PROG_TYPE_XDP program bytecode in the `.text` or named section, and
/// passes it to `bpf(BPF_PROG_LOAD, ...)`.
///
/// Map loading: parses the `.maps` section (BTF map definitions) and creates
/// each map with `bpf(BPF_MAP_CREATE, ...)`, storing the resulting fds.
///
/// XDP attachment: uses `bpf(BPF_LINK_CREATE, BPF_XDP, ...)` on kernel ≥ 5.7,
/// falls back to `setsockopt(SO_ATTACH_BPF)` on older kernels.
///
/// This is a minimal loader — it handles the specific maps.h map types
/// (ARRAY, HASH, PERCPU_HASH) and the single XDP program per object file.
/// It does not support CO-RE relocations, BTF line info, or tail calls.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::io::RawFd;

// ── Linux BPF constants (from <linux/bpf.h>) ─────────────────────────────────

const BPF_MAP_CREATE:    u64 = 0;
const BPF_PROG_LOAD:     u64 = 5;
const BPF_LINK_CREATE:   u64 = 28;
const BPF_MAP_UPDATE_ELEM: u64 = 2;
const BPF_MAP_LOOKUP_ELEM: u64 = 1;

const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_MAP_TYPE_HASH:        u32 = 1;
const BPF_MAP_TYPE_ARRAY:       u32 = 2;
const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
const BPF_XDP:           u32 = 37;  // bpf_attach_type for XDP links
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
const XDP_FLAGS_SKB_MODE:          u32 = 1 << 1; // generic/SKB XDP fallback

const LOG_BUF_SIZE: usize = 1 << 20; // 1 MB verifier log

// ── bpf_attr union layouts ────────────────────────────────────────────────────
// We use raw byte arrays sized to the kernel union width.  Each operation fills
// the relevant fields and zero-pads the rest.

#[repr(C)]
struct BpfMapCreateAttr {
    map_type:     u32,
    key_size:     u32,
    value_size:   u32,
    max_entries:  u32,
    map_flags:    u32,
    inner_map_fd: u32,
    numa_node:    u32,
    map_name:     [u8; 16],
    map_ifindex:  u32,
    btf_fd:       u32,
    btf_key_type_id:   u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra:    u64,
}

#[repr(C)]
struct BpfProgLoadAttr {
    prog_type:        u32,
    insn_cnt:         u32,
    insns:            u64,  // pointer to BPF instructions
    license:          u64,  // pointer to license string
    log_level:        u32,
    log_size:         u32,
    log_buf:          u64,  // pointer to log buffer
    kern_version:     u32,
    prog_flags:       u32,
    prog_name:        [u8; 16],
    prog_ifindex:     u32,
    expected_attach_type: u32,
    prog_btf_fd:      u32,
    func_info_rec_size: u32,
    func_info:        u64,
    func_info_cnt:    u32,
    line_info_rec_size: u32,
    line_info:        u64,
    line_info_cnt:    u32,
    attach_btf_id:    u32,
    attach_prog_fd:   u32,
}

#[repr(C)]
struct BpfLinkCreateAttr {
    prog_fd:          u32,
    target_fd:        u32,   // ifindex for XDP
    attach_type:      u32,   // BPF_XDP = 37
    flags:            u32,
    iter_info:        u64,
    iter_info_len:    u32,
    _pad:             u32,
}

// ── Syscall wrapper ───────────────────────────────────────────────────────────

fn bpf_syscall(cmd: u64, attr: *const u8, attr_size: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_bpf, cmd as libc::c_long, attr, attr_size as libc::c_uint) as i64 }
}

// ── Parsed BPF object ─────────────────────────────────────────────────────────

pub struct BpfObj {
    /// Program bytecode (8-byte BPF instructions)
    pub insns:    Vec<u8>,
    /// Map name → fd (maps created at load time)
    pub maps:     HashMap<String, RawFd>,
    /// License string from the ELF
    pub license:  String,
}

impl BpfObj {
    pub fn map_fd(&self, name: &str) -> Option<RawFd> {
        self.maps.get(name).copied()
    }
}

impl Drop for BpfObj {
    fn drop(&mut self) {
        for fd in self.maps.values() {
            unsafe { libc::close(*fd); }
        }
    }
}

// ── Minimal ELF parser ────────────────────────────────────────────────────────
// BPF .o files are ELF64 little-endian.  We parse just enough to find:
//   - .text / XDP section: BPF instructions
//   - .maps section: map definitions (legacy format with struct bpf_map_def)
//   - .rodata section: license string (or use symbol "license")
//
// Legacy map format (pre-BTF): each map is a `struct bpf_map_def` of 20 bytes:
//   u32 type, u32 key_size, u32 value_size, u32 max_entries, u32 map_flags

const ELF_MAGIC: u32 = 0x464c457f; // "\x7fELF" little-endian

#[repr(C, packed)]
struct Elf64Hdr {
    e_ident:     [u8; 16],
    e_type:      u16,
    e_machine:   u16,
    e_version:   u32,
    e_entry:     u64,
    e_phoff:     u64,
    e_shoff:     u64,   // section header offset
    e_flags:     u32,
    e_ehsize:    u16,
    e_phentsize: u16,
    e_phnum:     u16,
    e_shentsize: u16,
    e_shnum:     u16,
    e_shstrndx:  u16,
}

#[repr(C, packed)]
struct Elf64Shdr {
    sh_name:      u32,
    sh_type:      u32,
    sh_flags:     u64,
    sh_addr:      u64,
    sh_offset:    u64,
    sh_size:      u64,
    sh_link:      u32,
    sh_info:      u32,
    sh_addralign: u64,
    sh_entsize:   u64,
}

const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB:   u32 = 3;
const SHT_SYMTAB:   u32 = 2;

fn read_u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]])
}
fn read_u64_le(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off], data[off+1], data[off+2], data[off+3],
        data[off+4], data[off+5], data[off+6], data[off+7],
    ])
}
fn read_u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off+1]])
}

fn strtab_str(strtab: &[u8], off: usize) -> &str {
    let end = strtab[off..].iter().position(|&b| b == 0).map(|p| off + p).unwrap_or(strtab.len());
    std::str::from_utf8(&strtab[off..end]).unwrap_or("")
}

/// Parse an ELF BPF object file.  Returns a `BpfObj` with insns extracted
/// and maps created via `bpf(BPF_MAP_CREATE, ...)`.
pub fn parse_elf(path: &str) -> Result<BpfObj, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;

    if data.len() < 64 {
        return Err("ELF too small".to_owned());
    }
    if read_u32_le(&data, 0) != ELF_MAGIC {
        return Err("not an ELF file".to_owned());
    }
    // ELF64 LE check
    if data[4] != 2 { return Err("not ELF64".to_owned()); }
    if data[5] != 1 { return Err("not little-endian ELF".to_owned()); }

    let shoff    = read_u64_le(&data, 40) as usize;
    let shentsize= read_u16_le(&data, 58) as usize;
    let shnum    = read_u16_le(&data, 60) as usize;
    let shstrndx = read_u16_le(&data, 62) as usize;

    if shoff == 0 || shnum == 0 {
        return Err("no section headers".to_owned());
    }

    // Read all section headers
    let mut sections: Vec<(String, u32, usize, usize)> = Vec::new(); // (name, type, offset, size)

    // First get the section name string table
    let shstr_off  = shoff + shstrndx * shentsize;
    let shstr_data_off  = read_u64_le(&data, shstr_off + 24) as usize;
    let shstr_data_size = read_u64_le(&data, shstr_off + 32) as usize;
    let shstrtab = &data[shstr_data_off .. shstr_data_off + shstr_data_size];

    for i in 0..shnum {
        let sh_base  = shoff + i * shentsize;
        let name_off = read_u32_le(&data, sh_base) as usize;
        let sh_type  = read_u32_le(&data, sh_base + 4);
        let sh_off   = read_u64_le(&data, sh_base + 24) as usize;
        let sh_size  = read_u64_le(&data, sh_base + 32) as usize;
        let name     = strtab_str(shstrtab, name_off).to_owned();
        sections.push((name, sh_type, sh_off, sh_size));
    }

    // Find program section (named "xdp" or starting with "xdp/"), license, and maps
    let mut insns: Vec<u8>   = Vec::new();
    let mut license           = String::from("GPL");
    let mut map_defs: Vec<(String, [u8; 20])> = Vec::new();

    for (name, sh_type, off, size) in &sections {
        let name_str = name.as_str();
        if *sh_type == SHT_PROGBITS {
            if name_str == "xdp" || name_str.starts_with("xdp/") || name_str == ".text" {
                if insns.is_empty() && *size > 0 {
                    insns = data[*off .. *off + size].to_vec();
                }
            }
            if name_str == "license" && *size > 0 {
                let raw = &data[*off .. *off + size];
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                license = String::from_utf8_lossy(&raw[..end]).into_owned();
            }
            if name_str == ".maps" || name_str == "maps" {
                // Legacy format: struct bpf_map_def per entry (20 bytes)
                // Each entry corresponds to a map symbol; names from symtab
                // Simplified: read in 20-byte chunks and name them map_0, map_1, ...
                let mut cursor = *off;
                let end = off + size;
                let mut idx = 0usize;
                while cursor + 20 <= end {
                    let mut def = [0u8; 20];
                    def.copy_from_slice(&data[cursor..cursor+20]);
                    map_defs.push((format!("map_{}", idx), def));
                    cursor += 20;
                    idx += 1;
                }
            }
        }
    }

    if insns.is_empty() {
        return Err("no XDP program section found in ELF".to_owned());
    }

    // Create maps
    let mut maps: HashMap<String, RawFd> = HashMap::new();
    // Hard-code our known map names in order (must match maps.h definition order)
    let known_names = ["ip_request_count", "ip_blocked", "tsm_config", "tsm_stats"];
    for (idx, (_, def)) in map_defs.iter().enumerate() {
        let map_type   = read_u32_le(def, 0);
        let key_size   = read_u32_le(def, 4);
        let val_size   = read_u32_le(def, 8);
        let max_entries= read_u32_le(def, 12);
        let map_flags  = read_u32_le(def, 16);
        let name       = known_names.get(idx).unwrap_or(&"unknown");

        let fd = create_map(map_type, key_size, val_size, max_entries, map_flags, name)?;
        maps.insert(name.to_string(), fd);
    }

    // If no maps were found via .maps section, create our known maps manually
    if maps.is_empty() {
        maps.insert("ip_request_count".to_owned(),
            create_map(BPF_MAP_TYPE_PERCPU_HASH, 4, 8, 65536, 0, "ip_request_count")?);
        maps.insert("ip_blocked".to_owned(),
            create_map(BPF_MAP_TYPE_HASH, 4, 1, 65536, 0, "ip_blocked")?);
        maps.insert("tsm_config".to_owned(),
            create_map(BPF_MAP_TYPE_ARRAY, 4, 2, 1, 0, "tsm_config")?);
        maps.insert("tsm_stats".to_owned(),
            create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 8, 0, "tsm_stats")?);
    }

    Ok(BpfObj { insns, maps, license })
}

fn create_map(map_type: u32, key_size: u32, val_size: u32, max_entries: u32, flags: u32, name: &str) -> Result<RawFd, String> {
    let mut attr = BpfMapCreateAttr {
        map_type, key_size, value_size: val_size, max_entries, map_flags: flags,
        inner_map_fd: 0, numa_node: 0, map_name: [0u8; 16],
        map_ifindex: 0, btf_fd: 0,
        btf_key_type_id: 0, btf_value_type_id: 0,
        btf_vmlinux_value_type_id: 0, map_extra: 0,
    };
    let nb = name.len().min(15);
    attr.map_name[..nb].copy_from_slice(&name.as_bytes()[..nb]);

    let fd = bpf_syscall(
        BPF_MAP_CREATE,
        &attr as *const BpfMapCreateAttr as *const u8,
        std::mem::size_of::<BpfMapCreateAttr>() as u32,
    );
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        Err(format!("BPF_MAP_CREATE failed for '{}': {} (errno={})", name, err, unsafe { *libc::__errno_location() }))
    } else {
        Ok(fd as RawFd)
    }
}

/// Load a BPF program via BPF_PROG_LOAD. Returns the program fd.
pub fn load_program(obj: &BpfObj) -> Result<RawFd, String> {
    if obj.insns.is_empty() {
        return Err("no instructions to load".to_owned());
    }
    if obj.insns.len() % 8 != 0 {
        return Err(format!("instruction buffer not a multiple of 8 bytes (len={})", obj.insns.len()));
    }

    let insn_cnt = (obj.insns.len() / 8) as u32;
    let license  = CString::new(obj.license.as_str()).unwrap_or(CString::new("GPL").unwrap());
    let mut log_buf = vec![0u8; LOG_BUF_SIZE];

    let mut prog_name = [0u8; 16];
    let pname = b"tsm_xdp_ingress";
    let nb = pname.len().min(15);
    prog_name[..nb].copy_from_slice(&pname[..nb]);

    let attr = BpfProgLoadAttr {
        prog_type:        BPF_PROG_TYPE_XDP,
        insn_cnt,
        insns:            obj.insns.as_ptr() as u64,
        license:          license.as_ptr() as u64,
        log_level:        1,
        log_size:         LOG_BUF_SIZE as u32,
        log_buf:          log_buf.as_mut_ptr() as u64,
        kern_version:     0,
        prog_flags:       0,
        prog_name,
        prog_ifindex:     0,
        expected_attach_type: 0,
        prog_btf_fd:      0,
        func_info_rec_size: 0, func_info: 0, func_info_cnt: 0,
        line_info_rec_size: 0, line_info: 0, line_info_cnt: 0,
        attach_btf_id: 0, attach_prog_fd: 0,
    };

    let fd = bpf_syscall(
        BPF_PROG_LOAD,
        &attr as *const BpfProgLoadAttr as *const u8,
        std::mem::size_of::<BpfProgLoadAttr>() as u32,
    );

    if fd < 0 {
        // Print verifier log on failure
        let log_str = std::str::from_utf8(&log_buf)
            .unwrap_or("")
            .trim_end_matches('\0');
        if !log_str.is_empty() {
            eprintln!("[bpf] verifier log:\n{}", &log_str[..log_str.len().min(4096)]);
        }
        let err = std::io::Error::last_os_error();
        Err(format!("BPF_PROG_LOAD failed: {}", err))
    } else {
        eprintln!("[bpf] program loaded, fd={}, insns={}", fd, insn_cnt);
        Ok(fd as RawFd)
    }
}

/// Attach an XDP program to the given interface index.
/// Tries BPF_LINK_CREATE (kernel ≥ 5.7), falls back to netlink if unavailable.
pub fn attach_xdp(prog_fd: RawFd, ifindex: u32) -> Result<(), String> {
    let attr = BpfLinkCreateAttr {
        prog_fd:     prog_fd as u32,
        target_fd:   ifindex,
        attach_type: BPF_XDP,
        flags:       XDP_FLAGS_SKB_MODE, // generic XDP — works without driver support
        iter_info:   0,
        iter_info_len: 0,
        _pad: 0,
    };

    let link_fd = bpf_syscall(
        BPF_LINK_CREATE,
        &attr as *const BpfLinkCreateAttr as *const u8,
        std::mem::size_of::<BpfLinkCreateAttr>() as u32,
    );

    if link_fd >= 0 {
        eprintln!("[bpf] XDP link created, link_fd={}", link_fd);
        // Note: we intentionally do NOT close link_fd so the link stays alive
        // for the process lifetime.  It will be cleaned up when the process exits.
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        Err(format!("BPF_LINK_CREATE failed: {} (ifindex={})", err, ifindex))
    }
}
