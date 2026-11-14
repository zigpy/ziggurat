//! Reopening a lost RCP link.

use std::future::Future;
use std::time::Duration;

use tokio::time::{Instant, sleep};

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

/// Call `open` with backoff until it succeeds, or `None` once the policy's time is up.
pub async fn reopen<T, F, Fut>(policy: &ReconnectPolicy, mut open: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    let started = Instant::now();
    let mut attempt = 0;

    loop {
        attempt += 1;
        let delay = policy.backoff(attempt);
        if started.elapsed() + delay > policy.give_up_after {
            tracing::error!(
                "Giving up on the RCP link after {} attempts over {:?}",
                attempt - 1,
                started.elapsed()
            );
            return None;
        }

        sleep(delay).await;

        match open().await {
            Ok(transport) => {
                tracing::info!("RCP link reopened on attempt {attempt}");
                return Some(transport);
            }
            Err(err) => tracing::warn!("Reopening the RCP link failed (attempt {attempt}): {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// Attempt times, as offsets from the start, of `reopen` with an opener that fails
    /// `failures` times and then succeeds.
    async fn attempts(policy: ReconnectPolicy, failures: usize) -> (Vec<Duration>, Option<()>) {
        let started = Instant::now();
        let mut times = Vec::new();
        let result = reopen(&policy, || {
            times.push(started.elapsed());
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
        let (times, result) = attempts(ReconnectPolicy::default(), 2).await;

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
        let (times, result) = attempts(policy, usize::MAX).await;

        assert_eq!(result, None);
        assert_eq!(times.last(), Some(&Duration::from_millis(7500)));
        assert!(times.iter().all(|time| *time <= policy.give_up_after));
    }
}
