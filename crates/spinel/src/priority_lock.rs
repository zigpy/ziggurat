//! A priority-ordered async mutex.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

struct Waiter<P: Ord> {
    priority: P,
    seq: u64,
    grant: oneshot::Sender<PriorityGuard<P>>,
}

impl<P: Ord> Ord for Waiter<P> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Max-heap: higher priority first, then lower sequence (FIFO within a priority).
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl<P: Ord> PartialOrd for Waiter<P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<P: Ord> PartialEq for Waiter<P> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl<P: Ord> Eq for Waiter<P> {}

struct State<P: Ord> {
    held: bool,
    next_seq: u64,
    waiters: BinaryHeap<Waiter<P>>,
}

struct Inner<P: Ord> {
    state: Mutex<State<P>>,
}

impl<P: Ord> Inner<P> {
    /// Hand the lock to the highest-priority live waiter, if the lock is free. Caller holds
    /// the state lock; this never blocks and never re-enters it.
    fn grant_next(self: &Arc<Self>, state: &mut State<P>) {
        if state.held {
            return;
        }
        while let Some(waiter) = state.waiters.pop() {
            let guard = PriorityGuard {
                inner: Arc::clone(self),
                armed: true,
            };
            match waiter.grant.send(guard) {
                Ok(()) => {
                    state.held = true;
                    return;
                }
                Err(mut orphan) => {
                    // The acquirer was cancelled before being granted. Disarm the returned
                    // guard so its Drop does not re-enter the lock we currently hold, and
                    // try the next waiter. `held` was never set.
                    orphan.armed = false;
                }
            }
        }
    }

    fn release(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap();
        state.held = false;
        self.grant_next(&mut state);
        drop(state);
    }
}

pub struct PriorityLock<P: Ord> {
    inner: Arc<Inner<P>>,
}

impl<P: Ord + Send + 'static> PriorityLock<P> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    held: false,
                    next_seq: 0,
                    waiters: BinaryHeap::new(),
                }),
            }),
        }
    }

    pub async fn acquire(&self, priority: P) -> PriorityGuard<P> {
        let rx = {
            let mut state = self.inner.state.lock().unwrap();
            state.next_seq += 1;
            let seq = state.next_seq;
            let (grant, rx) = oneshot::channel();
            state.waiters.push(Waiter {
                priority,
                seq,
                grant,
            });
            self.inner.grant_next(&mut state);
            drop(state);
            rx
        };

        // Err is unreachable on the live path: a waiter's sender is dropped without sending
        // only after `grant_next` disarmed it, which happens precisely because this receiver
        // was already gone (the future cancelled), so this await never observes it.
        rx.await.expect("priority lock granted to a live waiter")
    }
}

impl<P: Ord + Send + 'static> Default for PriorityLock<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Ord> std::fmt::Debug for PriorityLock<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.inner.state.lock().unwrap();
        f.debug_struct("PriorityLock")
            .field("held", &state.held)
            .field("waiting", &state.waiters.len())
            .finish()
    }
}

/// Held lock. Releasing happens on drop, which hands the lock to the next waiter.
pub struct PriorityGuard<P: Ord> {
    inner: Arc<Inner<P>>,
    armed: bool,
}

impl<P: Ord> Drop for PriorityGuard<P> {
    fn drop(&mut self) {
        if self.armed {
            self.inner.release();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drains_in_priority_then_fifo_order() {
        let lock: Arc<PriorityLock<u8>> = Arc::new(PriorityLock::new());
        let held = lock.acquire(0).await; // block the lock so the rest queue

        let order = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for p in [1u8, 5, 3, 5] {
            let lock = Arc::clone(&lock);
            let order = Arc::clone(&order);
            handles.push(tokio::spawn(async move {
                let _g = lock.acquire(p).await;
                order.lock().unwrap().push(p);
            }));
            tokio::task::yield_now().await; // deterministic enqueue order ⇒ stable seqs
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        drop(held);
        for h in handles {
            h.await.unwrap();
        }
        // priority 5s first (FIFO between them), then 3, then 1
        assert_eq!(*order.lock().unwrap(), vec![5, 5, 3, 1]);
    }
}
