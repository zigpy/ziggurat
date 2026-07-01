//! `embassy-time` driver backed by RAIL's microsecond timer.
//!
//! `now()` reads RAIL's free-running microsecond clock (`sl_rail_get_time`, 32-bit, wraps
//! ~every 71 min) and extends it to 64 bits by counting wraps. Alarms use a single RAIL
//! multi-timer whose completion callback (radio IRQ context) services the embassy timer
//! queue. Tick rate is embassy-time's default 1 MHz, so ticks are microseconds directly.
//!
//! Requires the PHY to have initialized RAIL (`ziggurat_phy_efr32::rail_handle()` non-null)
//! and enabled the multi-timer; before that, `now()` reports 0 as the `Driver` contract
//! allows.

use core::cell::RefCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::Waker;

use critical_section::Mutex;
use embassy_time_driver::Driver;
use embassy_time_queue_utils::Queue;
use ziggurat_phy_efr32::rail_handle;
use ziggurat_rail_sys as rail;

const TIME_ABSOLUTE: rail::sl_rail_time_mode_t =
    rail::sl_rail_time_mode_t_enum::SL_RAIL_TIME_ABSOLUTE as rail::sl_rail_time_mode_t;

/// The one RAIL multi-timer node backing all embassy alarms. RAIL keeps a pointer to it, so
/// it must live forever; zeroed is the valid "unset" state.
static mut ALARM_TIMER: MaybeUninit<rail::sl_rail_multi_timer_t> = MaybeUninit::zeroed();

struct RailTimeDriver {
    queue: Mutex<RefCell<Queue>>,
    /// Number of 2^32-microsecond wraps observed by [`now`].
    period: AtomicU32,
    /// Last raw microsecond reading, for wrap detection.
    last: AtomicU32,
}

embassy_time_driver::time_driver_impl!(
    static DRIVER: RailTimeDriver = RailTimeDriver {
        queue: Mutex::new(RefCell::new(Queue::new())),
        period: AtomicU32::new(0),
        last: AtomicU32::new(0),
    }
);

fn raw_now() -> u32 {
    let h = rail_handle();
    if h.is_null() {
        return 0;
    }
    unsafe { rail::sl_rail_get_time(h) }
}

impl RailTimeDriver {
    /// 64-bit monotonic microseconds. Serialized under a critical section so wrap detection
    /// is atomic even when called from an interrupt.
    fn now64(&self) -> u64 {
        critical_section::with(|_| {
            let t = raw_now();
            let last = self.last.load(Ordering::Relaxed);
            let mut hi = self.period.load(Ordering::Relaxed);
            if t < last {
                hi = hi.wrapping_add(1);
                self.period.store(hi, Ordering::Relaxed);
            }
            self.last.store(t, Ordering::Relaxed);
            (u64::from(hi) << 32) | u64::from(t)
        })
    }

    /// Try to program (or cancel) the hardware alarm for deadline `at`. Returns `false` if
    /// `at` is already in the past (so RAIL would reject it and never fire) — the caller must
    /// then re-service the queue. `u64::MAX` disables the alarm and returns `true`.
    fn set_alarm(&self, at: u64) -> bool {
        let h = rail_handle();
        if h.is_null() {
            return true;
        }
        let timer = core::ptr::addr_of_mut!(ALARM_TIMER) as *mut rail::sl_rail_multi_timer_t;
        critical_section::with(|_| unsafe {
            if at == u64::MAX {
                rail::sl_rail_cancel_multi_timer(h, timer);
                return true;
            }
            // Bail if the deadline has already passed (checked with interrupts masked so it
            // can't slip past between the check and arming the timer).
            if at <= self.now64() {
                return false;
            }
            // RAIL's timer is 32-bit microseconds; the low word is the absolute deadline.
            rail::sl_rail_set_multi_timer(
                h,
                timer,
                at as u32,
                TIME_ABSOLUTE,
                Some(on_alarm),
                core::ptr::null_mut(),
            ) == 0
        })
    }

    /// Re-arm to the queue's next deadline, waking any already-expired timers. Loops so a
    /// deadline that lapses while arming is serviced rather than lost.
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

impl Driver for RailTimeDriver {
    fn now(&self) -> u64 {
        self.now64()
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        let changed = critical_section::with(|cs| self.queue.borrow_ref_mut(cs).schedule_wake(at, waker));
        if changed {
            self.rearm();
        }
    }
}

/// RAIL multi-timer completion, in radio IRQ context: wake expired timers and re-arm.
unsafe extern "C" fn on_alarm(
    _tmr: *mut rail::sl_rail_multi_timer_t,
    _expected: rail::sl_rail_time_t,
    _arg: *mut core::ffi::c_void,
) {
    DRIVER.rearm();
}
