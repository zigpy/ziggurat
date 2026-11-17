use core::time::Duration;

use crate::Instant;

/// When the next link status broadcast is due (spec 3.6.4.4.1): one period after the
/// last, or sooner when an early one was asked for.
#[derive(Debug, Default)]
pub struct LinkStatusSchedule {
    next: Instant,
}

impl LinkStatusSchedule {
    pub const fn next(&self) -> Instant {
        self.next
    }

    /// Ask for a link status broadcast by `at`. Returns whether the next one moved
    /// earlier: it stays where it is if it is already due sooner.
    pub fn bring_forward(&mut self, at: Instant) -> bool {
        let earlier = at < self.next;

        if earlier {
            self.next = at;
        }

        earlier
    }

    /// A link status broadcast goes out at `now`: the next one is due a `period` later.
    pub fn restart(&mut self, now: Instant, period: Duration) {
        self.next = now + period;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const PERIOD: Duration = Duration::from_secs(15);

    fn at(millis: u64) -> Instant {
        Instant::from_micros(0) + Duration::from_millis(millis)
    }

    fn started() -> LinkStatusSchedule {
        let mut schedule = LinkStatusSchedule::default();
        schedule.restart(at(0), PERIOD);
        schedule
    }

    #[test]
    fn test_requests_close_together_share_the_earliest_time() {
        let mut schedule = started();

        assert!(schedule.bring_forward(at(700)));
        assert!(!schedule.bring_forward(at(900)));
        assert!(schedule.bring_forward(at(600)));

        assert_eq!(schedule.next(), at(600));
    }

    #[test]
    fn test_request_after_the_period_end_changes_nothing() {
        let mut schedule = started();

        assert!(!schedule.bring_forward(at(15_500)));
        assert_eq!(schedule.next(), at(15_000));
    }

    #[test]
    fn test_broadcast_restarts_the_period() {
        let mut schedule = started();
        schedule.bring_forward(at(700));

        schedule.restart(at(700), PERIOD);
        assert_eq!(schedule.next(), at(15_700));
    }
}
