//! Broadcast admission budget.

use core::time::Duration;

use ziggurat_zigbee::Instant as CoreInstant;

use crate::frame_token::TrafficClass;

/// The outcome of asking the budget to admit one broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastAdmission {
    /// Send now.
    Admit,
    /// Refused: a token for this class frees no sooner than `retry_in`. Only
    /// [`TrafficClass::Forwarding`] and [`TrafficClass::Host`] are ever refused;
    /// [`TrafficClass::Critical`] always admits.
    Defer { retry_in: Duration },
}

/// A token bucket with per-class reserves.
#[derive(Debug)]
pub struct BroadcastBudget {
    /// Available tokens. Signed: a critical broadcast may overdraw below zero, which
    /// defers lower-class traffic until the bucket climbs back above their floors.
    tokens: i32,
    /// When the last whole token was accrued. Advanced in whole-token steps so the
    /// sub-token remainder of elapsed time is never discarded.
    last_refill: CoreInstant,
}

impl BroadcastBudget {
    /// A bucket that starts full at the stack's clock baseline (time zero).
    pub fn new(initial_tokens: u8) -> Self {
        Self {
            tokens: i32::from(initial_tokens),
            last_refill: CoreInstant::from_micros(0),
        }
    }

    /// The token floor a class may not dip into.
    fn floor(class: TrafficClass, critical_reserve: u8, forwarding_reserve: u8) -> i32 {
        match class {
            TrafficClass::Critical => 0,
            TrafficClass::Forwarding => i32::from(critical_reserve),
            TrafficClass::Host => i32::from(critical_reserve) + i32::from(forwarding_reserve),
        }
    }

    /// Regenerate one token per `refill_interval`, capped at `capacity`.
    fn refill(&mut self, now: CoreInstant, capacity: i32, refill_interval: Duration) {
        let interval_us = refill_interval.as_micros();

        // A zero interval means "no rate limit": keep the bucket full.
        if interval_us == 0 {
            self.tokens = capacity;
            self.last_refill = now;
            return;
        }

        // Already full (or clamped down after a tunable lowered the capacity): nothing
        // to add, but keep the clock current so a later deficit is measured from now.
        if self.tokens >= capacity {
            self.tokens = capacity;
            self.last_refill = now;
            return;
        }

        let elapsed_us = now.saturating_duration_since(self.last_refill).as_micros();
        let accrued = elapsed_us / interval_us;
        if accrued == 0 {
            return;
        }

        // `tokens < capacity` here, and overdraw is bounded at `-capacity`, so headroom
        // fits comfortably in the token range.
        let headroom = u128::try_from(capacity - self.tokens).unwrap_or(0);
        let added = accrued.min(headroom) as i32;
        self.tokens += added;

        if self.tokens >= capacity {
            self.tokens = capacity;
            self.last_refill = now;
        } else {
            self.last_refill = self.last_refill + refill_interval.saturating_mul(added as u32);
        }
    }

    /// Ask to admit one broadcast of `class`, refilling first.
    #[allow(clippy::too_many_arguments)]
    pub fn take(
        &mut self,
        class: TrafficClass,
        now: CoreInstant,
        capacity: u8,
        refill_interval: Duration,
        critical_reserve: u8,
        forwarding_reserve: u8,
    ) -> BroadcastAdmission {
        let capacity = i32::from(capacity);
        self.refill(now, capacity, refill_interval);

        if class == TrafficClass::Critical {
            // Bypass: necessary broadcasts are always admitted AND draw no token, so a
            // burst of them can never drive the bucket negative and lock out host or
            // forwarding traffic while it refills.
            BroadcastAdmission::Admit
        } else {
            let floor = Self::floor(class, critical_reserve, forwarding_reserve);
            if self.tokens > floor {
                self.tokens -= 1;
                BroadcastAdmission::Admit
            } else {
                let deficit = (floor + 1 - self.tokens).max(1) as u32;
                BroadcastAdmission::Defer {
                    retry_in: refill_interval.saturating_mul(deficit),
                }
            }
        }
    }
}
