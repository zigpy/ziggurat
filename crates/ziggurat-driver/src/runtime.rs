//! Async runtime abstraction layer.

use core::future::Future;
use core::ops::Add;
use core::time::Duration;

/// The instant type a [`Runtime`] measures time with. Bounded for exactly the
/// arithmetic the driver performs on deadlines.
pub trait RtInstant: Copy + Send + Sync + 'static + Add<Duration, Output = Self> {
    /// Saturating `self - earlier`, never panicking when `earlier` is in the future.
    fn saturating_duration_since(self, earlier: Self) -> Duration;
}

impl RtInstant for tokio::time::Instant {
    fn saturating_duration_since(self, earlier: Self) -> Duration {
        Self::saturating_duration_since(&self, earlier)
    }
}

/// A deadline elapsed before the awaited future completed. Replaces
/// `tokio::time::error::Elapsed` so the stack's error type stays runtime-agnostic.
#[derive(Debug, thiserror::Error)]
#[error("deadline elapsed")]
pub struct Elapsed;

/// The async runtime the driver runs on. Implemented by [`TokioRuntime`] for the
/// host server and (later) an embassy runtime for the MCU.
pub trait Runtime: Send + Sync + 'static {
    type Instant: RtInstant;

    /// The current monotonic instant.
    fn now() -> Self::Instant;

    /// Sleep for `duration`.
    fn sleep(duration: Duration) -> impl Future<Output = ()> + Send;

    /// Sleep until `deadline`.
    fn sleep_until(deadline: Self::Instant) -> impl Future<Output = ()> + Send;

    /// Run `future`, returning [`Elapsed`] if `duration` passes first.
    fn timeout<F>(
        duration: Duration,
        future: F,
    ) -> impl Future<Output = Result<F::Output, Elapsed>> + Send
    where
        F: Future + Send,
        F::Output: Send,
    {
        async move {
            let future = core::pin::pin!(future);
            let sleep = core::pin::pin!(Self::sleep(duration));
            match futures::future::select(future, sleep).await {
                futures::future::Either::Left((output, _)) => Ok(output),
                futures::future::Either::Right(((), _)) => Err(Elapsed),
            }
        }
    }

    /// Run `future`, returning [`Elapsed`] if `deadline` passes first.
    fn timeout_at<F>(
        deadline: Self::Instant,
        future: F,
    ) -> impl Future<Output = Result<F::Output, Elapsed>> + Send
    where
        F: Future + Send,
        F::Output: Send,
    {
        async move {
            let future = core::pin::pin!(future);
            let sleep = core::pin::pin!(Self::sleep_until(deadline));
            match futures::future::select(future, sleep).await {
                futures::future::Either::Left((output, _)) => Ok(output),
                futures::future::Either::Right(((), _)) => Err(Elapsed),
            }
        }
    }
}

/// The tokio runtime: the host server's executor.
#[derive(Debug, Clone, Copy)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    type Instant = tokio::time::Instant;

    fn now() -> Self::Instant {
        tokio::time::Instant::now()
    }

    fn sleep(duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }

    fn sleep_until(deadline: Self::Instant) -> impl Future<Output = ()> + Send {
        tokio::time::sleep_until(deadline)
    }
}
