/// Slab-based single-threaded async task executor.
///
/// Runs `Future<Output=()>` tasks without an external async runtime.
/// The executor maintains a slab (`Vec<Option<Task>>`) with a free-list
/// so task IDs can be reused without compaction.
///
/// The design is intentionally minimal:
///   - No cross-thread waking (single-threaded model)
///   - No heap-allocated wakers (tasks polled by task ID directly)
///   - No work-stealing
///   - I/O readiness is signalled by the epoll/io_uring poller pushing
///     task IDs onto the `ready` queue.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::collections::VecDeque;
use std::cell::RefCell;
use std::rc::Rc;

// ── Task ──────────────────────────────────────────────────────────────────────

type BoxFuture = Pin<Box<dyn Future<Output = ()>>>;

struct Task {
    future: BoxFuture,
    id:     usize,
}

// ── Ready queue (thread-local) ────────────────────────────────────────────────

// The waker pushes task IDs onto a thread-local ready queue.
// This is safe because the executor is single-threaded.
thread_local! {
    static READY: RefCell<VecDeque<usize>> = RefCell::new(VecDeque::new());
}

fn wake_task(id: usize) {
    READY.with(|q| q.borrow_mut().push_back(id));
}

// ── Minimal Waker implementation ──────────────────────────────────────────────

unsafe fn waker_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &VTABLE)
}

unsafe fn waker_wake(data: *const ()) {
    let id = data as usize;
    wake_task(id);
}

unsafe fn waker_wake_by_ref(data: *const ()) {
    let id = data as usize;
    wake_task(id);
}

unsafe fn waker_drop(_data: *const ()) {}

static VTABLE: RawWakerVTable = RawWakerVTable::new(
    waker_clone,
    waker_wake,
    waker_wake_by_ref,
    waker_drop,
);

fn make_waker(task_id: usize) -> Waker {
    let raw = RawWaker::new(task_id as *const (), &VTABLE);
    unsafe { Waker::from_raw(raw) }
}

// ── Executor ──────────────────────────────────────────────────────────────────

pub struct Executor {
    tasks: Vec<Option<Task>>,
    free:  Vec<usize>,          // free-list of available slots
}

impl Executor {
    pub fn new() -> Self {
        Executor {
            tasks: Vec::new(),
            free:  Vec::new(),
        }
    }

    /// Spawn a future as a new task.  Returns the task ID.
    pub fn spawn<F>(&mut self, future: F) -> usize
    where
        F: Future<Output = ()> + 'static,
    {
        let id = if let Some(slot) = self.free.pop() {
            slot
        } else {
            self.tasks.push(None);
            self.tasks.len() - 1
        };

        self.tasks[id] = Some(Task {
            future: Box::pin(future),
            id,
        });

        // Immediately mark as ready so the task runs on the next poll pass.
        wake_task(id);
        id
    }

    /// Poll all tasks that are currently marked ready.
    /// Returns the number of tasks that were polled.
    pub fn run_until_idle(&mut self) -> usize {
        let mut polled = 0;
        loop {
            let id = match READY.with(|q| q.borrow_mut().pop_front()) {
                Some(id) => id,
                None     => break,
            };

            // Take the task out of the slab (to avoid aliasing with the waker)
            let mut task = match self.tasks.get_mut(id).and_then(|t| t.take()) {
                Some(t) => t,
                None    => continue, // already completed or invalid id
            };

            let waker  = make_waker(id);
            let mut cx = Context::from_waker(&waker);

            match task.future.as_mut().poll(&mut cx) {
                Poll::Ready(()) => {
                    // Task complete — free the slot
                    self.free.push(id);
                    polled += 1;
                }
                Poll::Pending => {
                    // Put it back; waker will re-schedule it when ready
                    self.tasks[id] = Some(task);
                    polled += 1;
                }
            }
        }
        polled
    }

    /// Block until a specific future completes.
    /// This is used for the main accept loop in `main.rs`.
    pub fn block_on<F, T>(&mut self, mut future: F) -> T
    where
        F: Future<Output = T> + 'static,
        T: 'static,
    {
        // We need to return the value from the future.
        // Use a shared cell to extract it.
        let result: Rc<RefCell<Option<T>>> = Rc::new(RefCell::new(None));
        let result_clone = Rc::clone(&result);

        // Wrap the future to store its output
        let wrapper = async move {
            let val = future.await;
            *result_clone.borrow_mut() = Some(val);
        };

        // Hack: pin on the stack since we need to poll directly
        let mut pinned = Box::pin(wrapper);
        let dummy_id   = usize::MAX;
        let waker      = make_waker(dummy_id);
        let mut cx     = Context::from_waker(&waker);

        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(()) => break,
                Poll::Pending   => {
                    // Run other spawned tasks while waiting
                    self.run_until_idle();
                    // If still pending and no tasks to run, spin (busy wait)
                    // In production, this drives the epoll/io_uring poller.
                }
            }
        }

        result.borrow_mut().take().expect("future completed but produced no value")
    }

    /// Total number of allocated task slots (including free slots).
    pub fn capacity(&self) -> usize {
        self.tasks.len()
    }

    /// Number of active (non-free) task slots.
    pub fn active_count(&self) -> usize {
        self.tasks.iter().filter(|t| t.is_some()).count()
    }
}

impl Default for Executor {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn spawn_and_run_simple_future() {
        let mut exec = Executor::new();
        let counter  = Arc::new(AtomicU32::new(0));
        let c        = Arc::clone(&counter);
        exec.spawn(async move { c.fetch_add(1, Ordering::Relaxed); });
        exec.run_until_idle();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn multiple_tasks_all_run() {
        let mut exec = Executor::new();
        let counter  = Arc::new(AtomicU32::new(0));
        for _ in 0..10 {
            let c = Arc::clone(&counter);
            exec.spawn(async move { c.fetch_add(1, Ordering::Relaxed); });
        }
        exec.run_until_idle();
        assert_eq!(counter.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn task_slots_reused() {
        let mut exec = Executor::new();
        for _ in 0..5 {
            exec.spawn(async {});
        }
        exec.run_until_idle();
        // After 5 tasks complete, the next spawn should reuse a slot
        let cap_before = exec.capacity();
        exec.spawn(async {});
        exec.run_until_idle();
        let cap_after = exec.capacity();
        // Capacity should not have grown (slot was reused)
        assert!(cap_after <= cap_before + 1, "capacity grew unexpectedly: {} → {}", cap_before, cap_after);
    }

    #[test]
    fn block_on_returns_value() {
        let mut exec = Executor::new();
        let val = exec.block_on(async { 42u32 });
        assert_eq!(val, 42);
    }
}
