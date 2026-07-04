//! `embassy-time` driver over the platform layer: `now` reads the firmware's monotonic
//! microsecond clock (`otPlatTimeGet`), alarms use the glue's single one-shot timer
//! whose completion calls `ziggurat_timer_fired`. Tick rate is embassy-time's default
//! 1 MHz, so ticks are microseconds.

use core::cell::RefCell;
use core::task::Waker;

use critical_section::Mutex;
use embassy_time_driver::Driver;
use embassy_time_queue_utils::Queue;

use crate::platform;

struct OtTimeDriver {
    queue: Mutex<RefCell<Queue>>,
}

embassy_time_driver::time_driver_impl!(
    static DRIVER: OtTimeDriver = OtTimeDriver {
        queue: Mutex::new(RefCell::new(Queue::new())),
    }
);

impl OtTimeDriver {
    fn now64(&self) -> u64 {
        unsafe { platform::ziggurat_platform_time_now_us() }
    }

    /// Try to program (or cancel) the glue timer for deadline `at`. Returns `false` if
    /// `at` is already in the past — the caller must then re-service the queue.
    /// `u64::MAX` disables the timer and returns `true`.
    fn set_alarm(&self, at: u64) -> bool {
        if at == u64::MAX {
            unsafe { platform::ziggurat_platform_timer_arm(u64::MAX) };
            return true;
        }
        if at <= self.now64() {
            return false;
        }
        unsafe { platform::ziggurat_platform_timer_arm(at) };
        true
    }

    /// Re-arm to the queue's next deadline, waking any already-expired timers. Loops so
    /// a deadline that lapses while arming is serviced rather than lost.
    fn rearm(&self) {
        critical_section::with(|cs| {
            let mut queue = self.queue.borrow_ref_mut(cs);
            loop {
                let next = queue.next_expiration(self.now64());
                if self.set_alarm(next) {
                    break;
                }
            }
        });
    }
}

impl Driver for OtTimeDriver {
    fn now(&self) -> u64 {
        self.now64()
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        let changed =
            critical_section::with(|cs| self.queue.borrow_ref_mut(cs).schedule_wake(at, waker));
        if changed {
            self.rearm();
        }
    }
}

/// The glue timer fired (OpenThread main-loop context): wake expired timers and re-arm.
pub fn timer_fired() {
    DRIVER.rearm();
}
