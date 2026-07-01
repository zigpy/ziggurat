use core::ops::Add;
use core::time::Duration;

/// A monotonic instant, as microseconds since an arbitrary epoch chosen by the driver.
///
/// The sans-io core never reads a clock; the driver passes `now` in and converts its own
/// platform clock (tokio, embassy, a sim) to and from this type at the boundary. Replacing
/// `std::time::Instant` is what lets this crate build for `no_std` targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    micros: u64,
}

impl Instant {
    pub const fn from_micros(micros: u64) -> Self {
        Self { micros }
    }

    pub const fn as_micros(&self) -> u64 {
        self.micros
    }

    /// Saturating elapsed time since `earlier`; zero if `earlier` is in the future.
    pub const fn saturating_duration_since(&self, earlier: Self) -> Duration {
        Duration::from_micros(self.micros.saturating_sub(earlier.micros))
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    /// Saturating: a "never" sentinel built from a huge `Duration` clamps instead of
    /// panicking on overflow.
    fn add(self, rhs: Duration) -> Self {
        let add = u64::try_from(rhs.as_micros()).unwrap_or(u64::MAX);
        Self {
            micros: self.micros.saturating_add(add),
        }
    }
}
