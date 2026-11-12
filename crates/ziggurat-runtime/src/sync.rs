//! The synchronization primitives the stack rests on: a blocking [`Mutex`], an async
//! [`AsyncMutex`], and a [`Notify`]. None of them depends on an executor.

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::{Future, poll_fn};
use core::ops::{Deref, DerefMut};
use core::task::{Poll, Waker};

#[cfg(feature = "std")]
pub use parking_lot::{Mutex, MutexGuard};

// A spinlock is a guard-returning, `Sync`, no_std mutex. On the cooperative single-core
// MCU executor it never actually spins, and the stack never holds a guard across an
// `.await`, so the lock window is always brief.
#[cfg(not(feature = "std"))]
pub use spin::{Mutex, MutexGuard};

/// A wake for one waiting task.
///
/// `notify_one` stores one permit and repeats coalesce; `notified` consumes it. Only one
/// task may wait at a time: a second waiter replaces the first one's registration.
pub struct Notify {
    state: Mutex<NotifyState>,
}

struct NotifyState {
    permit: bool,
    waiter: Option<Waker>,
}

impl Notify {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(NotifyState {
                permit: false,
                waiter: None,
            }),
        }
    }

    pub fn notify_one(&self) {
        let waiter = {
            let mut state = self.state.lock();
            state.permit = true;
            state.waiter.take()
        };

        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    pub fn notified(&self) -> impl Future<Output = ()> + Send + '_ {
        poll_fn(|cx| {
            let mut state = self.state.lock();

            if state.permit {
                state.permit = false;
                state.waiter = None;
                Poll::Ready(())
            } else {
                state.waiter = Some(cx.waker().clone());
                Poll::Pending
            }
        })
    }
}

impl Default for Notify {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Notify {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Notify")
    }
}

/// A mutex whose guard may be held across an `.await`.
///
/// Not fair: an unlock wakes every waiter and the first one polled takes the lock.
pub struct AsyncMutex<T> {
    state: Mutex<AsyncMutexState>,
    value: UnsafeCell<T>,
}

struct AsyncMutexState {
    locked: bool,
    waiters: Vec<Waker>,
}

// SAFETY: `value` is only reached through an `AsyncMutexGuard`, and `locked` admits one
// guard at a time, so the mutex hands `T` between threads without sharing it.
unsafe impl<T: Send> Send for AsyncMutex<T> {}
unsafe impl<T: Send> Sync for AsyncMutex<T> {}

impl<T> AsyncMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: Mutex::new(AsyncMutexState {
                locked: false,
                waiters: Vec::new(),
            }),
            value: UnsafeCell::new(value),
        }
    }

    pub fn try_lock(&self) -> Option<AsyncMutexGuard<'_, T>> {
        let mut state = self.state.lock();

        if state.locked {
            return None;
        }

        state.locked = true;
        drop(state);

        Some(AsyncMutexGuard { mutex: self })
    }

    pub fn lock(&self) -> impl Future<Output = AsyncMutexGuard<'_, T>> + Send + '_
    where
        T: Send,
    {
        poll_fn(|cx| {
            let mut state = self.state.lock();

            if state.locked {
                if !state.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                    state.waiters.push(cx.waker().clone());
                }
                return Poll::Pending;
            }

            state.locked = true;
            drop(state);

            Poll::Ready(AsyncMutexGuard { mutex: self })
        })
    }
}

impl<T> core::fmt::Debug for AsyncMutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AsyncMutex")
    }
}

pub struct AsyncMutexGuard<'a, T> {
    mutex: &'a AsyncMutex<T>,
}

// SAFETY: the guard is exclusive access to `T`, so it follows the rules of `&mut T`.
unsafe impl<T: Send> Send for AsyncMutexGuard<'_, T> {}
unsafe impl<T: Sync> Sync for AsyncMutexGuard<'_, T> {}

impl<T> Deref for AsyncMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: this guard exists, so no other guard does.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for AsyncMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this guard exists, so no other guard does.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for AsyncMutexGuard<'_, T> {
    fn drop(&mut self) {
        let waiters = {
            let mut state = self.mutex.state.lock();
            state.locked = false;
            core::mem::take(&mut state.waiters)
        };

        for waiter in waiters {
            waiter.wake();
        }
    }
}
