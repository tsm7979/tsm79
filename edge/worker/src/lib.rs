//! TSM edge worker — sandboxed WebAssembly policy, run by the C++ edge host.
//!
//! Cloudflare/Fastly "Workers" model: untrusted, multi-tenant code compiled to
//! Wasm and executed in a memory-safe sandbox with CPU (fuel) + memory limits.
//! Developers can write workers in *any* language that targets Wasm; this one
//! is Rust `no_std` so it has zero runtime and a tiny footprint.
//!
//! ABI (kept deliberately minimal):
//!   - export `memory`            — the worker's linear memory (provided automatically)
//!   - export `input_ptr() -> i32`— address of the request buffer the host writes into
//!   - export `input_cap() -> i32`— capacity of that buffer
//!   - export `on_request(len) -> i32` — verdict for the `len` request bytes at input_ptr
//!
//! Verdict: 0 = allow, 1 = block, 2 = redact.

#![no_std]

use core::panic::PanicInfo;

// Host-provided API (the "Workers" capability surface). The worker can only
// touch the outside world through these imports — the sandbox grants nothing else.
#[link(wasm_import_module = "tsm")]
extern "C" {
    fn log(ptr: *const u8, len: i32);
}

fn host_log(msg: &[u8]) {
    unsafe { log(msg.as_ptr(), msg.len() as i32) }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    // A trap is the sandbox-safe failure mode; the host treats it as "block".
    core::arch::wasm32::unreachable()
}

const CAP: usize = 8192;
static mut INPUT: [u8; CAP] = [0u8; CAP];

#[no_mangle]
pub extern "C" fn input_ptr() -> i32 {
    // SAFETY: returning the address of a 'static buffer; the host only writes
    // up to input_cap() bytes into it before calling on_request.
    unsafe { INPUT.as_ptr() as i32 }
}

#[no_mangle]
pub extern "C" fn input_cap() -> i32 {
    CAP as i32
}

#[no_mangle]
pub extern "C" fn on_request(len: i32) -> i32 {
    let n = if len < 0 { 0 } else if (len as usize) > CAP { CAP } else { len as usize };
    let buf = unsafe { &INPUT[..n] };

    // Demonstrate the host capability surface: the worker calls back into the host.
    host_log(buf);

    // Edge policy: block internal/admin surfaces; redact secret-bearing paths.
    if contains(buf, b"/admin") || contains(buf, b"/internal") || contains(buf, b"/.git") {
        return 1; // block
    }
    if contains(buf, b"secret") || contains(buf, b"token") || contains(buf, b"apikey") {
        return 2; // redact
    }
    0 // allow
}

/// Naive substring search (no_std, no allocations).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}
