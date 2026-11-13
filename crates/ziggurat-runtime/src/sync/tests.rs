use alloc::boxed::Box;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use super::*;

#[test]
fn test_failed_try_lock_leaves_the_lock_held() {
    let mutex = AsyncMutex::new(());
    let guard = mutex.try_lock().unwrap();

    assert!(mutex.try_lock().is_none());
    assert!(mutex.try_lock().is_none());

    drop(guard);
    assert!(mutex.try_lock().is_some());
}

#[test]
fn test_lock_is_handed_to_waiters_in_order() {
    let mut cx = Context::from_waker(Waker::noop());
    let mutex = AsyncMutex::new(());

    let guard = mutex.try_lock().unwrap();
    let mut first = Box::pin(mutex.lock());
    let mut second = Box::pin(mutex.lock());
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());

    // The lock goes to the first waiter. Nobody can take it before that waiter runs
    drop(guard);
    assert!(mutex.try_lock().is_none());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    let mut late = Box::pin(mutex.lock());
    assert!(late.as_mut().poll(&mut cx).is_pending());

    let Poll::Ready(guard) = first.as_mut().poll(&mut cx) else {
        panic!("the first waiter should hold the lock");
    };
    drop(guard);

    assert!(late.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_ready());
}

#[test]
fn test_waiter_that_gives_up_passes_the_lock_on() {
    let mut cx = Context::from_waker(Waker::noop());
    let mutex = AsyncMutex::new(());

    let guard = mutex.try_lock().unwrap();
    let mut handed = Box::pin(mutex.lock());
    let mut queued = Box::pin(mutex.lock());
    let mut last = Box::pin(mutex.lock());
    assert!(handed.as_mut().poll(&mut cx).is_pending());
    assert!(queued.as_mut().poll(&mut cx).is_pending());
    assert!(last.as_mut().poll(&mut cx).is_pending());

    // One waiter gives up after the lock was handed to it, one while still queued
    drop(guard);
    drop(handed);
    drop(queued);

    let Poll::Ready(guard) = last.as_mut().poll(&mut cx) else {
        panic!("the last waiter should hold the lock");
    };
    drop(guard);
    assert!(mutex.try_lock().is_some());
}

#[test]
fn test_notify_stores_one_permit() {
    let mut cx = Context::from_waker(Waker::noop());
    let notify = Notify::new();

    // Repeats before anyone waits count once
    notify.notify_one();
    notify.notify_one();
    assert!(pin!(notify.notified()).poll(&mut cx).is_ready());

    let mut waiting = pin!(notify.notified());
    assert!(waiting.as_mut().poll(&mut cx).is_pending());

    notify.notify_one();
    assert!(waiting.as_mut().poll(&mut cx).is_ready());
}
