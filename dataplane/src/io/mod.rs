pub mod executor;
pub mod poller;

// io_uring is Linux-only
#[cfg(target_os = "linux")]
pub mod uring;

pub use executor::Executor;
pub use poller::{Poller, Interest, Event, set_nonblocking, set_reuseaddr, set_nodelay};

#[cfg(target_os = "linux")]
pub use uring::{UringRing, uring_available, Sqe, Cqe,
                IORING_OP_RECV, IORING_OP_SEND, IORING_OP_ACCEPT};
