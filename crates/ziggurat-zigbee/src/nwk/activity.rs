use core::time::Duration;

use crate::Instant;

const STEPS_PER_COUNT: u16 = 256;

/// A spec activity counter (`RecentActivity`, `RouterOutboundActivity`,
/// `RouterInboundActivity`).
///
/// It is held in steps of 1/256 of a count, so it decays by the time that has passed
/// and not once per period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activity {
    steps: u16,
}

impl Activity {
    const MAX_STEPS: u16 = u8::MAX as u16 * STEPS_PER_COUNT;

    pub const fn new(count: u8) -> Self {
        Self {
            steps: count as u16 * STEPS_PER_COUNT,
        }
    }

    /// The whole counts held.
    pub const fn count(&self) -> u8 {
        (self.steps / STEPS_PER_COUNT) as u8
    }

    pub fn record_use(&mut self) {
        self.steps = self
            .steps
            .saturating_add(STEPS_PER_COUNT)
            .min(Self::MAX_STEPS);
    }

    pub const fn decay(&mut self, steps: u16) {
        self.steps = self.steps.saturating_sub(steps);
    }
}

/// The decay steps owed for the time from `*decayed_at` to `now`, at one count per
/// `period`. `*decayed_at` moves forward by the steps returned, so the rest of the time
/// counts toward the next call.
pub fn take_decay_steps(decayed_at: &mut Instant, now: Instant, period: Duration) -> u16 {
    let step = period / u32::from(STEPS_PER_COUNT);
    let elapsed = now.saturating_duration_since(*decayed_at).as_micros() / step.as_micros();
    let steps = u16::try_from(elapsed).unwrap_or(u16::MAX);

    *decayed_at = *decayed_at + step * u32::from(steps);
    steps
}

#[cfg(test)]
mod test {
    use super::*;

    const PERIOD: Duration = Duration::from_secs(16);

    fn at(millis: u64) -> Instant {
        Instant::from_micros(0) + Duration::from_millis(millis)
    }

    #[test]
    fn test_activity_decays_by_the_time_passed() {
        let mut activity = Activity::new(3);
        let mut decayed_at = at(0);

        // Half a period is half a count: the whole count drops from 3 to 2
        activity.decay(take_decay_steps(&mut decayed_at, at(8_000), PERIOD));
        assert_eq!(activity.count(), 2);

        // The same instant again owes nothing
        assert_eq!(take_decay_steps(&mut decayed_at, at(8_000), PERIOD), 0);

        // The other half completes one whole count of decay
        activity.decay(take_decay_steps(&mut decayed_at, at(16_000), PERIOD));
        assert_eq!(activity, Activity::new(2));
    }

    #[test]
    fn test_time_shorter_than_a_step_carries_over() {
        let mut decayed_at = at(0);

        // One step is 16 s / 256 = 62.5 ms
        assert_eq!(take_decay_steps(&mut decayed_at, at(60), PERIOD), 0);
        assert_eq!(take_decay_steps(&mut decayed_at, at(125), PERIOD), 2);
    }

    #[test]
    fn test_activity_stays_between_0_and_255() {
        let mut activity = Activity::new(254);
        activity.record_use();
        activity.record_use();
        assert_eq!(activity, Activity::new(255));

        activity.decay(u16::MAX);
        assert_eq!(activity, Activity::new(0));
    }
}
