//! Broadcast admission budget.

use core::time::Duration;

use crate::Instant;

/// Which tier of the broadcast budget admits a broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    /// A frame we originate on the host's behalf: refused first under pressure, the
    /// host is told and can pace itself.
    Host,
    /// A transit frame relayed for another device: dropping one degrades the mesh but
    /// the originator retries end-to-end.
    Forwarding,
    /// Optional stack work, such as route refresh: refused first under pressure, and it
    /// never draws the tokens kept for host traffic. The caller tries again later.
    Background,
    /// Stack machinery the mesh cannot function without: joins, APS acks, NWK
    /// commands, indirect deliveries. Always admitted.
    Critical,
}

/// The outcome of asking the budget to admit one broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastAdmission {
    /// Send now.
    Admit,
    /// Refused: a token for this class frees no sooner than `retry_in`. Only
    /// [`TrafficClass::Background`], [`TrafficClass::Forwarding`] and
    /// [`TrafficClass::Host`] are ever refused;
    /// [`TrafficClass::Critical`] always admits.
    Defer { retry_in: Duration },
}

/// A token bucket with per-class reserves.
#[derive(Debug)]
pub struct BroadcastBudget {
    /// Available tokens. Critical broadcasts bypass the bucket and draw nothing; host
    /// and forwarding traffic only draws above its floor, so the count never dips below
    /// zero. Background traffic stops higher still, above the host reserve.
    tokens: u32,
    /// When the last whole token was accrued. Advanced in whole-token steps so the
    /// sub-token remainder of elapsed time is never discarded.
    last_refill: Instant,
}

impl BroadcastBudget {
    /// A bucket that starts full at the stack's clock baseline (time zero).
    pub fn new(initial_tokens: u8) -> Self {
        Self {
            tokens: u32::from(initial_tokens),
            last_refill: Instant::from_micros(0),
        }
    }

    /// The token floor a class may not dip into.
    fn floor(
        class: TrafficClass,
        critical_reserve: u8,
        forwarding_reserve: u8,
        host_reserve: u8,
    ) -> u32 {
        match class {
            TrafficClass::Critical => 0,
            TrafficClass::Forwarding => u32::from(critical_reserve),
            TrafficClass::Host => u32::from(critical_reserve) + u32::from(forwarding_reserve),
            TrafficClass::Background => {
                u32::from(critical_reserve)
                    + u32::from(forwarding_reserve)
                    + u32::from(host_reserve)
            }
        }
    }

    /// Regenerate one token per `refill_interval`, capped at `capacity`.
    fn refill(&mut self, now: Instant, capacity: u32, refill_interval: Duration) {
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

        // `tokens < capacity` here, so headroom fits comfortably in the token range.
        let headroom = u128::from(capacity - self.tokens);
        let added = accrued.min(headroom) as u32;
        self.tokens += added;

        if self.tokens >= capacity {
            self.tokens = capacity;
            self.last_refill = now;
        } else {
            self.last_refill = self.last_refill + refill_interval.saturating_mul(added);
        }
    }

    /// Ask to admit one broadcast of `class`, refilling first.
    #[allow(clippy::too_many_arguments)]
    pub fn take(
        &mut self,
        class: TrafficClass,
        now: Instant,
        capacity: u8,
        refill_interval: Duration,
        critical_reserve: u8,
        forwarding_reserve: u8,
        host_reserve: u8,
    ) -> BroadcastAdmission {
        let capacity = u32::from(capacity);
        self.refill(now, capacity, refill_interval);

        if class == TrafficClass::Critical {
            // Bypass: necessary broadcasts are always admitted AND draw no token, so a
            // burst of them can never lock out host or forwarding traffic while it
            // refills.
            BroadcastAdmission::Admit
        } else {
            let floor = Self::floor(class, critical_reserve, forwarding_reserve, host_reserve);
            if self.tokens > floor {
                self.tokens -= 1;
                BroadcastAdmission::Admit
            } else {
                let deficit = floor + 1 - self.tokens;
                BroadcastAdmission::Defer {
                    retry_in: refill_interval.saturating_mul(deficit),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: u8 = 10;
    const REFILL: Duration = Duration::from_secs(1);
    const CRITICAL_RESERVE: u8 = 1;
    const FORWARDING_RESERVE: u8 = 1;
    const HOST_RESERVE: u8 = 3;
    /// Background broadcasts may not draw the last five tokens.
    const BACKGROUND_FLOOR: u8 = CRITICAL_RESERVE + FORWARDING_RESERVE + HOST_RESERVE;

    const START: Instant = Instant::from_micros(0);

    fn take(budget: &mut BroadcastBudget, class: TrafficClass) -> BroadcastAdmission {
        budget.take(
            class,
            START,
            CAPACITY,
            REFILL,
            CRITICAL_RESERVE,
            FORWARDING_RESERVE,
            HOST_RESERVE,
        )
    }

    /// A budget, never refilled during the test, holding `tokens`.
    fn budget_with(tokens: u8) -> BroadcastBudget {
        let mut budget = BroadcastBudget::new(CAPACITY);
        for _ in tokens..CAPACITY {
            assert_eq!(
                take(&mut budget, TrafficClass::Host),
                BroadcastAdmission::Admit
            );
        }
        budget
    }

    #[test]
    fn test_background_above_its_floor_is_admitted() {
        let mut budget = budget_with(BACKGROUND_FLOOR + 1);

        assert_eq!(
            take(&mut budget, TrafficClass::Background),
            BroadcastAdmission::Admit
        );
    }

    #[test]
    fn test_admitted_background_draws_a_token() {
        let mut budget = budget_with(BACKGROUND_FLOOR + 1);
        take(&mut budget, TrafficClass::Background);

        assert_eq!(
            take(&mut budget, TrafficClass::Background),
            BroadcastAdmission::Defer { retry_in: REFILL }
        );
    }

    #[test]
    fn test_background_at_its_floor_is_deferred() {
        let mut budget = budget_with(BACKGROUND_FLOOR);

        assert!(matches!(
            take(&mut budget, TrafficClass::Background),
            BroadcastAdmission::Defer { .. }
        ));
    }

    #[test]
    fn test_host_is_admitted_where_background_is_deferred() {
        let mut budget = budget_with(BACKGROUND_FLOOR);

        assert_eq!(
            take(&mut budget, TrafficClass::Host),
            BroadcastAdmission::Admit
        );
    }

    #[test]
    fn test_deferred_background_waits_for_the_tokens_it_lacks() {
        let mut budget = budget_with(BACKGROUND_FLOOR - 2);

        assert_eq!(
            take(&mut budget, TrafficClass::Background),
            BroadcastAdmission::Defer {
                retry_in: REFILL * 3
            }
        );
    }
}
