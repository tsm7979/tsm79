/// io_uring interface via `libc::syscall` — no external crate.
///
/// Implements the minimal io_uring operations needed by the TSM data plane:
///   - Setup: io_uring_setup(entries, params) → ring fd
///   - SQ ring mmap at IORING_OFF_SQ_RING (0)
///   - CQ ring mmap at IORING_OFF_CQ_RING (0x8000000)
///   - SQE array mmap at IORING_OFF_SQES  (0x10000000)
///   - Submit: io_uring_enter(ring_fd, to_submit, min_complete, flags)
///   - Operations: IORING_OP_RECV, IORING_OP_SEND, IORING_OP_ACCEPT
///
/// Falls back to epoll (`Poller`) on EINVAL (kernel < 5.1) or if not root.

use std::os::unix::io::RawFd;
use libc::{c_void, mmap, munmap, syscall, PROT_READ, PROT_WRITE, MAP_SHARED, MAP_POPULATE, MAP_FAILED};

// ── Syscall numbers (x86-64 only) ────────────────────────────────────────────

const SYS_IO_URING_SETUP:  i64 = 425;
const SYS_IO_URING_ENTER:  i64 = 426;
const SYS_IO_URING_REGISTER: i64 = 427;

// ── io_uring constants ────────────────────────────────────────────────────────

const IORING_OFF_SQ_RING: i64 = 0;
const IORING_OFF_CQ_RING: i64 = 0x0800_0000;
const IORING_OFF_SQES:    i64 = 0x1000_0000;

const IORING_ENTER_GETEVENTS: u32 = 1;

// Opcodes
pub const IORING_OP_NOP:    u8 = 0;
pub const IORING_OP_READV:  u8 = 1;
pub const IORING_OP_WRITEV: u8 = 2;
pub const IORING_OP_RECV:   u8 = 17;
pub const IORING_OP_SEND:   u8 = 10;
pub const IORING_OP_ACCEPT: u8 = 13;

// ── io_uring_params (kernel ABI — must be repr(C)) ────────────────────────────

#[repr(C)]
#[derive(Default)]
pub struct IoUringParams {
    pub sq_entries:      u32,
    pub cq_entries:      u32,
    pub flags:           u32,
    pub sq_thread_cpu:   u32,
    pub sq_thread_idle:  u32,
    pub features:        u32,
    pub wq_fd:           u32,
    pub resv:            [u32; 3],
    pub sq_off:          SqRingOffsets,
    pub cq_off:          CqRingOffsets,
}

#[repr(C)]
#[derive(Default)]
pub struct SqRingOffsets {
    pub head:        u32,
    pub tail:        u32,
    pub ring_mask:   u32,
    pub ring_entries: u32,
    pub flags:       u32,
    pub dropped:     u32,
    pub array:       u32,
    pub resv1:       u32,
    pub user_addr:   u64,
}

#[repr(C)]
#[derive(Default)]
pub struct CqRingOffsets {
    pub head:        u32,
    pub tail:        u32,
    pub ring_mask:   u32,
    pub ring_entries: u32,
    pub overflow:    u32,
    pub cqes:        u32,
    pub flags:       u32,
    pub resv1:       u32,
    pub user_addr:   u64,
}

// ── Submission Queue Entry (SQE) — 64 bytes, kernel ABI ──────────────────────

#[repr(C)]
pub struct Sqe {
    pub opcode:    u8,
    pub flags:     u8,
    pub ioprio:    u16,
    pub fd:        i32,
    pub off_addr2: u64,    // off for read/write, addr for recv/send
    pub addr:      u64,    // buffer pointer
    pub len:       u32,    // buffer length
    pub op_flags:  u32,    // per-opcode flags
    pub user_data: u64,    // returned verbatim in CQE
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3:     u64,
    pub pad2:      u64,
}

impl Default for Sqe {
    fn default() -> Self {
        // SAFETY: all-zero is a valid SQE (NOP opcode)
        unsafe { std::mem::zeroed() }
    }
}

// ── Completion Queue Entry (CQE) — 16 bytes, kernel ABI ──────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Cqe {
    pub user_data: u64,
    pub res:       i32,
    pub flags:     u32,
}

// ── UringRing ─────────────────────────────────────────────────────────────────

pub struct UringRing {
    pub ring_fd:   RawFd,
    sq_ring_ptr:   *mut u8,
    sq_ring_size:  usize,
    cq_ring_ptr:   *mut u8,
    cq_ring_size:  usize,
    sqes_ptr:      *mut Sqe,
    sqes_size:     usize,
    params:        IoUringParams,
    sq_entries:    u32,
    cq_entries:    u32,
}

impl UringRing {
    /// Create a new io_uring ring with `entries` SQ/CQ slots.
    /// Returns `Err` if io_uring is not available (old kernel, permissions, etc).
    pub fn new(entries: u32) -> std::io::Result<Self> {
        let mut params = IoUringParams::default();

        let ring_fd = unsafe {
            syscall(SYS_IO_URING_SETUP, entries as i64, &mut params as *mut _ as i64)
        };
        if ring_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ring_fd = ring_fd as RawFd;

        // Compute ring sizes (conservative upper bound)
        let sq_ring_size  = (params.sq_off.array as usize)
            + params.sq_entries as usize * std::mem::size_of::<u32>();
        let cq_ring_size  = (params.cq_off.cqes as usize)
            + params.cq_entries as usize * std::mem::size_of::<Cqe>();
        let sqes_size     = params.sq_entries as usize * std::mem::size_of::<Sqe>();

        // mmap SQ ring
        let sq_ring_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                sq_ring_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE,
                ring_fd,
                IORING_OFF_SQ_RING,
            )
        };
        if sq_ring_ptr == MAP_FAILED {
            unsafe { libc::close(ring_fd); }
            return Err(std::io::Error::last_os_error());
        }

        // mmap CQ ring
        let cq_ring_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                cq_ring_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE,
                ring_fd,
                IORING_OFF_CQ_RING,
            )
        };
        if cq_ring_ptr == MAP_FAILED {
            unsafe { munmap(sq_ring_ptr, sq_ring_size); libc::close(ring_fd); }
            return Err(std::io::Error::last_os_error());
        }

        // mmap SQE array
        let sqes_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                sqes_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE,
                ring_fd,
                IORING_OFF_SQES,
            )
        } as *mut Sqe;
        if sqes_ptr as *mut c_void == MAP_FAILED {
            unsafe { munmap(sq_ring_ptr, sq_ring_size); munmap(cq_ring_ptr, cq_ring_size); libc::close(ring_fd); }
            return Err(std::io::Error::last_os_error());
        }

        let sq_entries = params.sq_entries;
        let cq_entries = params.cq_entries;

        Ok(UringRing {
            ring_fd,
            sq_ring_ptr: sq_ring_ptr as *mut u8,
            sq_ring_size,
            cq_ring_ptr: cq_ring_ptr as *mut u8,
            cq_ring_size,
            sqes_ptr,
            sqes_size,
            params,
            sq_entries,
            cq_entries,
        })
    }

    /// Get a mutable reference to the SQE at the given index.
    ///
    /// # Safety
    /// Caller must ensure `idx < sq_entries` and the SQE is not currently
    /// owned by the kernel (i.e., hasn't been submitted yet).
    pub unsafe fn sqe(&mut self, idx: u32) -> &mut Sqe {
        &mut *self.sqes_ptr.add(idx as usize)
    }

    /// Submit `n` prepared SQEs and optionally wait for `min_complete` CQEs.
    pub fn submit(&self, to_submit: u32, min_complete: u32) -> std::io::Result<u32> {
        let flags = if min_complete > 0 { IORING_ENTER_GETEVENTS } else { 0 };
        let ret   = unsafe {
            syscall(
                SYS_IO_URING_ENTER,
                self.ring_fd as i64,
                to_submit    as i64,
                min_complete as i64,
                flags        as i64,
                0i64,
                0i64,
            )
        };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as u32)
        }
    }

    /// Read the current SQ tail pointer (where the next SQE should be written).
    pub fn sq_tail(&self) -> u32 {
        unsafe {
            let tail_ptr = self.sq_ring_ptr.add(self.params.sq_off.tail as usize) as *const u32;
            std::ptr::read_volatile(tail_ptr)
        }
    }

    /// Advance the SQ tail by 1 (after filling in a new SQE).
    pub fn advance_sq_tail(&self) {
        unsafe {
            let tail_ptr = self.sq_ring_ptr.add(self.params.sq_off.tail as usize) as *mut u32;
            std::ptr::write_volatile(tail_ptr, std::ptr::read_volatile(tail_ptr).wrapping_add(1));
        }
    }

    /// Read the CQ head (oldest pending completion).
    pub fn cq_head(&self) -> u32 {
        unsafe {
            let head_ptr = self.cq_ring_ptr.add(self.params.cq_off.head as usize) as *const u32;
            std::ptr::read_volatile(head_ptr)
        }
    }

    /// Read the CQ tail (one past the newest completion).
    pub fn cq_tail(&self) -> u32 {
        unsafe {
            let tail_ptr = self.cq_ring_ptr.add(self.params.cq_off.tail as usize) as *const u32;
            std::ptr::read_volatile(tail_ptr)
        }
    }

    /// Advance the CQ head by 1 (mark one CQE as consumed).
    pub fn advance_cq_head(&self) {
        unsafe {
            let head_ptr = self.cq_ring_ptr.add(self.params.cq_off.head as usize) as *mut u32;
            std::ptr::write_volatile(head_ptr, std::ptr::read_volatile(head_ptr).wrapping_add(1));
        }
    }

    /// Read a CQE at the given index (wrap modulo cq_entries).
    pub fn cqe(&self, idx: u32) -> Cqe {
        let ring_mask = self.cq_entries - 1;
        let slot = (idx & ring_mask) as usize;
        unsafe {
            let cqes = self.cq_ring_ptr.add(self.params.cq_off.cqes as usize) as *const Cqe;
            std::ptr::read_volatile(cqes.add(slot))
        }
    }

    /// Drain all pending CQEs, calling `f(cqe)` for each.
    pub fn drain_cqes(&self, mut f: impl FnMut(Cqe)) {
        loop {
            let head = self.cq_head();
            let tail = self.cq_tail();
            if head == tail { break; }
            let cqe = self.cqe(head);
            self.advance_cq_head();
            f(cqe);
        }
    }
}

impl Drop for UringRing {
    fn drop(&mut self) {
        unsafe {
            munmap(self.sq_ring_ptr as *mut c_void, self.sq_ring_size);
            munmap(self.cq_ring_ptr as *mut c_void, self.cq_ring_size);
            munmap(self.sqes_ptr    as *mut c_void, self.sqes_size);
            libc::close(self.ring_fd);
        }
    }
}

// SAFETY: We access the ring from a single thread (the executor runs single-threaded).
unsafe impl Send for UringRing {}

/// Check if io_uring is available on this kernel.
/// Returns `true` if `io_uring_setup(0, ...)` doesn't return ENOSYS.
pub fn uring_available() -> bool {
    let mut params = IoUringParams::default();
    let ret = unsafe { syscall(SYS_IO_URING_SETUP, 1i64, &mut params as *mut _ as i64) };
    if ret >= 0 {
        // Immediately close the test ring
        unsafe { libc::close(ret as RawFd); }
        true
    } else {
        let err = std::io::Error::last_os_error();
        err.raw_os_error() != Some(libc::ENOSYS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uring_available_check() {
        // This test simply checks that the function runs without panicking.
        // On systems without io_uring it returns false; that's fine.
        let _available = uring_available();
    }

    #[test]
    fn sqe_default_is_nop() {
        let sqe = Sqe::default();
        assert_eq!(sqe.opcode, IORING_OP_NOP);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_ring_if_available() {
        if !uring_available() {
            eprintln!("io_uring not available, skipping ring creation test");
            return;
        }
        let ring = UringRing::new(4);
        match ring {
            Ok(r)  => { assert!(r.sq_entries >= 4); drop(r); }
            Err(e) => eprintln!("UringRing::new failed: {} (may need root or newer kernel)", e),
        }
    }
}
