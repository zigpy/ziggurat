//! The synchronization primitives the stack rests on: a blocking [`Mutex`], an async
//! [`AsyncMutex`], and an [`Notify`].
//!
//! Everything in the driver imports these from here rather than naming `parking_lot`,
//! `tokio`, `spin`, or `embassy-sync` directly, so this module is the single seam where
//! the implementation is chosen by the `embassy` feature. The blocking [`Mutex`] must
//! never be held across an `.await` (the protocol core's
//! [`CoreGuard`](crate::zigbee_stack::CoreGuard) enforces this by being `!Send`); use
//! [`AsyncMutex`] for the few guards that genuinely outlive an await point.

#[cfg(not(feature = "embassy"))]
mod imp {
    pub use parking_lot::{Mutex, MutexGuard};
    pub use tokio::sync::Mutex as AsyncMutex;
    pub use tokio::sync::Notify;
}

#[cfg(feature = "embassy")]
mod imp {
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;

    // A spinlock is a guard-returning, `Sync`, no_std mutex; on the cooperative
    // single-core MCU executor it never actually spins, and the stack never holds a guard
    // across an `.await`, so the lock window is always brief.
    pub use spin::{Mutex, MutexGuard};

    /// The async mutex, for guards held across an `.await` (the radio stream + reset
    /// receivers). Pinned to the critical-section raw mutex.
    pub type AsyncMutex<T> = embassy_sync::mutex::Mutex<CriticalSectionRawMutex, T>;

    /// A parameterless wake matching `tokio::sync::Notify`'s surface.
    ///
    /// Built over embassy's single-slot [`Signal`](embassy_sync::signal::Signal):
    /// `notify_one` stores one permit and coalesces repeats; `notified` consumes it — the
    /// same single-waiter contract every wake in the stack relies on.
    #[derive(Default)]
    pub struct Notify(embassy_sync::signal::Signal<CriticalSectionRawMutex, ()>);

    impl Notify {
        pub const fn new() -> Self {
            Self(embassy_sync::signal::Signal::new())
        }

        pub fn notify_one(&self) {
            self.0.signal(());
        }

        pub async fn notified(&self) {
            self.0.wait().await;
        }
    }

    impl core::fmt::Debug for Notify {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("Notify")
        }
    }
}

pub use imp::*;
