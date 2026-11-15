//! Reopening a lost RCP link.

use std::future::Future;
use std::time::Duration;

use tokio::time::{Instant, sleep, timeout};

/// How a lost RCP link is reopened: exponential backoff from `initial_backoff`, capped
/// at `max_backoff`, abandoned once `give_up_after` has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectPolicy {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub give_up_after: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(5),
            give_up_after: Duration::from_secs(60),
        }
    }
}

impl ReconnectPolicy {
    /// The delay before reopen attempt `attempt`, counting from 1.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
        self.initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

/// One loss of the RCP link, from when it was lost until the RCP answers again. It may
/// span several reopened links that never got an answer.
#[derive(Debug)]
pub struct Outage {
    started: Instant,
    attempts: u32,
}

impl Outage {
    pub fn start() -> Self {
        Self {
            started: Instant::now(),
            attempts: 0,
        }
    }

    /// Call `open` with backoff until it succeeds, or `None` once the policy's time
    /// since the outage started is up.
    pub async fn reopen<T, F, Fut>(&mut self, policy: &ReconnectPolicy, mut open: F) -> Option<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = std::io::Result<T>>,
    {
        loop {
            self.attempts += 1;
            let delay = policy.backoff(self.attempts);
            if self.started.elapsed() + delay > policy.give_up_after {
                return self.give_up();
            }

            sleep(delay).await;

            // A connect that hangs must not outlast the outage's time either
            let remaining = policy.give_up_after.saturating_sub(self.started.elapsed());
            match timeout(remaining, open()).await {
                Ok(Ok(transport)) => {
                    tracing::info!("RCP link reopened on attempt {}", self.attempts);
                    return Some(transport);
                }
                Ok(Err(err)) => tracing::warn!(
                    "Reopening the RCP link failed (attempt {}): {err}",
                    self.attempts
                ),
                Err(_) => return self.give_up(),
            }
        }
    }

    fn give_up<T>(&self) -> Option<T> {
        tracing::error!(
            "Giving up on the RCP link after {} attempts over {:?}",
            self.attempts,
            self.started.elapsed()
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// Reopen with an opener that fails `failures` times and then succeeds. Returns
    /// the attempt times, as offsets from `origin`.
    async fn attempts(
        outage: &mut Outage,
        policy: &ReconnectPolicy,
        origin: Instant,
        failures: usize,
    ) -> (Vec<Duration>, Option<()>) {
        let mut times = Vec::new();
        let result = outage
            .reopen(policy, || {
                times.push(origin.elapsed());
                let result = if times.len() > failures {
                    Ok(())
                } else {
                    Err(io::Error::from(io::ErrorKind::NotFound))
                };
                async move { result }
            })
            .await;

        (times, result)
    }

    #[test]
    fn test_backoff_doubles_up_to_the_cap() {
        let policy = ReconnectPolicy::default();
        let delays: Vec<u64> = (1..=6)
            .map(|attempt| policy.backoff(attempt).as_millis() as u64)
            .collect();

        assert_eq!(delays, [500, 1000, 2000, 4000, 5000, 5000]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_reopen_retries_with_backoff_until_it_succeeds() {
        let origin = Instant::now();
        let (times, result) =
            attempts(&mut Outage::start(), &ReconnectPolicy::default(), origin, 2).await;

        assert_eq!(
            times,
            [
                Duration::from_millis(500),
                Duration::from_millis(1500),
                Duration::from_millis(3500),
            ]
        );
        assert_eq!(result, Some(()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_reopen_gives_up_within_its_time() {
        let policy = ReconnectPolicy {
            give_up_after: Duration::from_secs(12),
            ..ReconnectPolicy::default()
        };
        let origin = Instant::now();
        let (times, result) = attempts(&mut Outage::start(), &policy, origin, usize::MAX).await;

        assert_eq!(result, None);
        assert_eq!(times.last(), Some(&Duration::from_millis(7500)));
        assert!(times.iter().all(|time| *time <= policy.give_up_after));
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_later_reopen_of_the_same_outage_keeps_its_deadline() {
        let policy = ReconnectPolicy {
            give_up_after: Duration::from_secs(6),
            ..ReconnectPolicy::default()
        };
        let origin = Instant::now();
        let mut outage = Outage::start();
        attempts(&mut outage, &policy, origin, 0).await;
        // The reopened link failed again after a while
        sleep(Duration::from_secs(5)).await;

        let (times, result) = attempts(&mut outage, &policy, origin, usize::MAX).await;

        assert_eq!(result, None);
        assert!(times.iter().all(|time| *time <= policy.give_up_after));
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_later_reopen_of_the_same_outage_continues_the_backoff() {
        let origin = Instant::now();
        let mut outage = Outage::start();
        attempts(&mut outage, &ReconnectPolicy::default(), origin, 0).await;

        let (times, _) = attempts(&mut outage, &ReconnectPolicy::default(), origin, 0).await;

        // The second attempt waits 1 s, after the first at 0.5 s
        assert_eq!(times, [Duration::from_millis(1500)]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_an_open_that_hangs_is_abandoned_at_the_deadline() {
        let policy = ReconnectPolicy {
            give_up_after: Duration::from_secs(5),
            ..ReconnectPolicy::default()
        };
        let origin = Instant::now();

        let result: Option<()> = Outage::start()
            .reopen(&policy, std::future::pending::<io::Result<()>>)
            .await;

        assert_eq!(result, None);
        assert_eq!(origin.elapsed(), policy.give_up_after);
    }
}
