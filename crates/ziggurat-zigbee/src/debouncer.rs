//! A timer that fires at a fixed interval, or sooner when asked.

use core::time::Duration;

use crate::Instant;

/// A periodic deadline that a request can move earlier. A burst of requests fires once.
#[derive(Debug, Default)]
pub struct Debouncer {
    next: Instant,
}

impl Debouncer {
    pub const fn next(&self) -> Instant {
        self.next
    }

    /// Ask for a firing by `at`. Returns whether the next firing moved earlier: it
    /// stays where it is if it is already due sooner.
    pub fn request(&mut self, at: Instant) -> bool {
        let earlier = at < self.next;

        if earlier {
            self.next = at;
        }

        earlier
    }

    /// It fires at `now`: the next firing is due an `interval` later.
    pub fn fired(&mut self, now: Instant, interval: Duration) {
        self.next = now + interval;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const INTERVAL: Duration = Duration::from_secs(15);

    fn at(millis: u64) -> Instant {
        Instant::from_micros(0) + Duration::from_millis(millis)
    }

    fn started() -> Debouncer {
        let mut debouncer = Debouncer::default();
        debouncer.fired(at(0), INTERVAL);
        debouncer
    }

    #[test]
    fn test_requests_close_together_share_the_earliest_time() {
        let mut debouncer = started();

        assert!(debouncer.request(at(700)));
        assert!(!debouncer.request(at(900)));
        assert!(debouncer.request(at(600)));

        assert_eq!(debouncer.next(), at(600));
    }

    #[test]
    fn test_request_after_the_interval_end_changes_nothing() {
        let mut debouncer = started();

        assert!(!debouncer.request(at(15_500)));
        assert_eq!(debouncer.next(), at(15_000));
    }

    #[test]
    fn test_firing_restarts_the_interval() {
        let mut debouncer = started();
        debouncer.request(at(700));

        debouncer.fired(at(700), INTERVAL);
        assert_eq!(debouncer.next(), at(15_700));
    }
}
