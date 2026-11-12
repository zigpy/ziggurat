//! The synchronization primitives the stack rests on: a blocking [`Mutex`], an async
//! [`AsyncMutex`], and a [`Notify`]. None of them depends on an executor.

use alloc::collections::VecDeque;
use core::cell::UnsafeCell;
use core::future::{Future, poll_fn};
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

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
pub struct AsyncMutex<T> {
    state: Mutex<AsyncMutexState>,
    value: UnsafeCell<T>,
}

struct AsyncMutexState {
    locked: bool,
    next_waiter: u64,
    /// Oldest first.
    waiters: VecDeque<(u64, Waker)>,
    /// The waiter an unlock handed the lock to, until that waiter collects it.
    handed_to: Option<u64>,
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
                next_waiter: 0,
                waiters: VecDeque::new(),
                handed_to: None,
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

    pub const fn lock(&self) -> AsyncMutexLock<'_, T> {
        AsyncMutexLock {
            mutex: self,
            waiter: None,
        }
    }

    /// Hand the lock to the oldest waiter, or release it when nobody waits. The lock
    /// stays `locked` across a handoff, so nothing can take it in between.
    fn unlock(&self) {
        let waker = {
            let mut state = self.state.lock();

            match state.waiters.pop_front() {
                Some((waiter, waker)) => {
                    state.handed_to = Some(waiter);
                    Some(waker)
                }
                None => {
                    state.locked = false;
                    None
                }
            }
        };

        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The future returned by [`AsyncMutex::lock`].
pub struct AsyncMutexLock<'a, T> {
    mutex: &'a AsyncMutex<T>,
    /// Our place in the queue, once the first poll found the mutex locked.
    waiter: Option<u64>,
}

impl<'a, T> Future for AsyncMutexLock<'a, T> {
    type Output = AsyncMutexGuard<'a, T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mutex = self.mutex;
        let mut state = mutex.state.lock();

        match self.waiter {
            None if !state.locked => {
                state.locked = true;
            }
            None => {
                let waiter = state.next_waiter;
                state.next_waiter += 1;
                state.waiters.push_back((waiter, cx.waker().clone()));
                drop(state);

                self.waiter = Some(waiter);
                return Poll::Pending;
            }
            Some(waiter) if state.handed_to == Some(waiter) => {
                state.handed_to = None;
            }
            Some(waiter) => {
                for (queued, waker) in &mut state.waiters {
                    if *queued == waiter {
                        waker.clone_from(cx.waker());
                    }
                }
                return Poll::Pending;
            }
        }
        drop(state);

        self.waiter = None;
        Poll::Ready(AsyncMutexGuard { mutex })
    }
}

impl<T> Drop for AsyncMutexLock<'_, T> {
    /// A waiter that gives up leaves the queue, and passes on a lock it was already handed.
    fn drop(&mut self) {
        let Some(waiter) = self.waiter else {
            return;
        };

        let handed = {
            let mut state = self.mutex.state.lock();

            if state.handed_to == Some(waiter) {
                state.handed_to = None;
                true
            } else {
                state.waiters.retain(|(queued, _)| *queued != waiter);
                false
            }
        };

        if handed {
            self.mutex.unlock();
        }
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
        self.mutex.unlock();
    }
}
