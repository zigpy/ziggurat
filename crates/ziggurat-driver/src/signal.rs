//! `Signal` primitive: effectively a `Mutex` plus a `Notify`.

use core::fmt;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::sync::Notify;

/// The producer was dropped without ever signalling a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed;

enum State<T> {
    /// No value yet, producer still alive.
    Pending,
    /// A value was signalled and not yet taken.
    Ready(T),
    /// The producer was dropped without signalling.
    Closed,
}

struct Inner<T> {
    slot: Mutex<State<T>>,
    ready: Notify,
}

/// The producer half. Signalling (or dropping) it wakes the [`SignalWaiter`].
pub struct Signal<T> {
    inner: Arc<Inner<T>>,
}

/// The consumer half. [`wait`](SignalWaiter::wait) resolves once the producer signals a
/// value or is dropped.
pub struct SignalWaiter<T> {
    inner: Arc<Inner<T>>,
}

/// Create a producer/waiter pair sharing a single-value slot.
pub fn channel<T>() -> (Signal<T>, SignalWaiter<T>) {
    let inner = Arc::new(Inner {
        slot: Mutex::new(State::Pending),
        ready: Notify::new(),
    });
    (
        Signal {
            inner: inner.clone(),
        },
        SignalWaiter { inner },
    )
}

impl<T> Signal<T> {
    /// Hand `value` to the waiter. A dropped waiter just discards it.
    pub fn signal(self, value: T) {
        *self.inner.slot.lock() = State::Ready(value);
        self.inner.ready.notify_one();
        // `self` drops here; `Drop` sees `Ready` and leaves the value in place.
    }
}

impl<T> Drop for Signal<T> {
    fn drop(&mut self) {
        let closed = {
            let mut state = self.inner.slot.lock();
            if matches!(*state, State::Pending) {
                *state = State::Closed;
                true
            } else {
                false
            }
        };
        if closed {
            self.inner.ready.notify_one();
        }
    }
}

impl<T> SignalWaiter<T> {
    /// Wait for the producer to signal a value, or `Err(Closed)` if it was dropped first.
    pub async fn wait(&self) -> Result<T, Closed> {
        loop {
            // `notify_one` stores a permit when no waiter is registered, so a signal that
            // lands between the check and the await is not lost.
            if let Some(result) = self.take() {
                return result;
            }
            self.inner.ready.notified().await;
        }
    }

    fn take(&self) -> Option<Result<T, Closed>> {
        let mut state = self.inner.slot.lock();
        let result = match core::mem::replace(&mut *state, State::Pending) {
            State::Pending => None,
            State::Ready(value) => Some(Ok(value)),
            State::Closed => {
                *state = State::Closed;
                Some(Err(Closed))
            }
        };
        drop(state);
        result
    }
}

impl<T> fmt::Debug for Signal<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signal")
    }
}

impl<T> fmt::Debug for SignalWaiter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignalWaiter")
    }
}
