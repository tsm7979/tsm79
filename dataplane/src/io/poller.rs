/// epoll-based I/O readiness poller — Linux kernel interface via libc.
///
/// Used as the fallback when io_uring is unavailable (kernel < 5.1) or
/// when running on non-Linux platforms (dev mode).
///
/// The `Poller` manages a single epoll file descriptor and exposes:
///   - `add(fd, interest)` — register interest in read/write/both
///   - `modify(fd, interest)` — change interest for an existing fd
///   - `remove(fd)` — deregister an fd
///   - `wait(events, timeout_ms)` — block until events are ready (or timeout)

use std::os::unix::io::RawFd;
use libc::{
    epoll_create1, epoll_ctl, epoll_event, epoll_wait,
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
    EPOLLIN, EPOLLOUT, EPOLLET, EPOLLERR, EPOLLHUP, EPOLLRDHUP,
    close,
};

// ── Interest flags ────────────────────────────────────────────────────────────

bitflags! {
    pub struct Interest: u32 {
        const READABLE  = EPOLLIN  as u32;
        const WRITABLE  = EPOLLOUT as u32;
        const EDGE      = EPOLLET  as u32;
        const ERROR     = EPOLLERR as u32;
        const HANGUP    = EPOLLHUP as u32;
        const READ_CLOSE = EPOLLRDHUP as u32;
    }
}

/// Implement a minimal bitflags! macro inline to avoid the crate dependency.
#[macro_export]
macro_rules! bitflags {
    (pub struct $name:ident: $ty:ty { $(const $flag:ident = $val:expr;)* }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub $ty);
        impl $name {
            $( pub const $flag: $name = $name($val); )*
            pub fn contains(self, other: $name) -> bool { (self.0 & other.0) == other.0 }
            pub fn bits(self) -> $ty { self.0 }
        }
        impl std::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self { $name(self.0 | rhs.0) }
        }
        impl std::ops::BitAnd for $name {
            type Output = Self;
            fn bitand(self, rhs: Self) -> Self { $name(self.0 & rhs.0) }
        }
    }
}

// Re-define Interest using the inline macro since we can't use the bitflags crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interest(pub u32);
impl Interest {
    pub const READABLE:   Interest = Interest(EPOLLIN  as u32);
    pub const WRITABLE:   Interest = Interest(EPOLLOUT as u32);
    pub const EDGE:       Interest = Interest(EPOLLET  as u32);
    pub const ERROR:      Interest = Interest(EPOLLERR as u32);
    pub const HANGUP:     Interest = Interest(EPOLLHUP as u32);
    pub const READ_CLOSE: Interest = Interest(EPOLLRDHUP as u32);
    pub const READ_WRITE: Interest = Interest(EPOLLIN as u32 | EPOLLOUT as u32);

    pub fn contains(self, other: Interest) -> bool { (self.0 & other.0) == other.0 }
    pub fn bits(self) -> u32 { self.0 }
}
impl std::ops::BitOr for Interest {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Interest(self.0 | rhs.0) }
}

/// A ready event returned from `Poller::wait`.
#[derive(Debug)]
pub struct Event {
    pub fd:   RawFd,
    pub ready: Interest,
}

// ── Poller ────────────────────────────────────────────────────────────────────

pub struct Poller {
    epfd: RawFd,
}

impl Poller {
    /// Create a new epoll instance.
    pub fn new() -> std::io::Result<Self> {
        let epfd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if epfd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Poller { epfd })
    }

    /// Register `fd` with the given interest flags.
    /// The `token` is stored in `u64 data` so it can be retrieved in events.
    pub fn add(&self, fd: RawFd, interest: Interest, token: u64) -> std::io::Result<()> {
        let mut ev = epoll_event {
            events: interest.bits() | EPOLLET as u32,
            u64:    token,
        };
        let rc = unsafe { epoll_ctl(self.epfd, EPOLL_CTL_ADD, fd, &mut ev) };
        if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Modify the interest flags for an already-registered `fd`.
    pub fn modify(&self, fd: RawFd, interest: Interest, token: u64) -> std::io::Result<()> {
        let mut ev = epoll_event {
            events: interest.bits(),
            u64:    token,
        };
        let rc = unsafe { epoll_ctl(self.epfd, EPOLL_CTL_MOD, fd, &mut ev) };
        if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Remove `fd` from the epoll instance.
    pub fn remove(&self, fd: RawFd) -> std::io::Result<()> {
        let rc = unsafe { epoll_ctl(self.epfd, EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
        if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Wait for ready events.  Returns a slice of `Event`s written into `events`.
    ///
    /// `timeout_ms` — milliseconds to wait; -1 = block forever; 0 = return immediately.
    pub fn wait(&self, events: &mut Vec<Event>, max: usize, timeout_ms: i32) -> std::io::Result<usize> {
        let mut raw: Vec<epoll_event> = vec![epoll_event { events: 0, u64: 0 }; max];
        let n = unsafe { epoll_wait(self.epfd, raw.as_mut_ptr(), max as i32, timeout_ms) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        events.clear();
        for i in 0..n as usize {
            events.push(Event {
                fd:    raw[i].u64 as RawFd,
                ready: Interest(raw[i].events),
            });
        }
        Ok(n as usize)
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        unsafe { close(self.epfd); }
    }
}

impl Default for Poller {
    fn default() -> Self { Self::new().expect("epoll_create1 failed") }
}

// ── Non-blocking helpers ──────────────────────────────────────────────────────

/// Set O_NONBLOCK on a file descriptor.
pub fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 { return Err(std::io::Error::last_os_error()); }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

/// Set SO_REUSEADDR on a socket.
pub fn set_reuseaddr(fd: RawFd) -> std::io::Result<()> {
    let opt: i32 = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

/// Set TCP_NODELAY on a socket.
pub fn set_nodelay(fd: RawFd) -> std::io::Result<()> {
    let opt: i32 = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn poller_create_and_drop() {
        let p = Poller::new().expect("epoll_create failed");
        drop(p); // should close the epfd without panic
    }

    #[test]
    fn add_and_remove_pipe() {
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        let (read_fd, write_fd) = (fds[0], fds[1]);

        let p = Poller::new().unwrap();
        p.add(read_fd, Interest::READABLE, read_fd as u64).unwrap();
        p.remove(read_fd).unwrap();

        unsafe { libc::close(read_fd); libc::close(write_fd); }
    }

    #[test]
    fn wait_times_out() {
        let p = Poller::new().unwrap();
        let mut events = Vec::new();
        let n = p.wait(&mut events, 32, 1).unwrap(); // 1ms timeout
        assert_eq!(n, 0);
    }

    #[test]
    fn pipe_readable_detected() {
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        let (read_fd, write_fd) = (fds[0], fds[1]);
        set_nonblocking(read_fd).unwrap();

        let p = Poller::new().unwrap();
        p.add(read_fd, Interest::READABLE, read_fd as u64).unwrap();

        // Write to the pipe to make it readable
        let byte = b'x';
        unsafe { libc::write(write_fd, &byte as *const _ as *const _, 1) };

        let mut events = Vec::new();
        let n = p.wait(&mut events, 32, 100).unwrap();
        assert!(n > 0, "should detect readable event");
        assert!(events[0].ready.contains(Interest::READABLE));

        unsafe { libc::close(read_fd); libc::close(write_fd); }
    }
}
