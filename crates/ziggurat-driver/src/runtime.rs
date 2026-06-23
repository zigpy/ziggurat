//! Async runtime abstraction layer.

use core::future::Future;
use core::ops::Add;
use core::pin::Pin;
use core::time::Duration;

/// A detached background task, boxed so one spawn path serves every runtime.
///
/// Tokio drops it into a tracked `JoinSet`; embassy (later) hands it to a static
/// task-pool runner. Our tasks capture only `Arc<ZigbeeStack>` and never hold a
/// `CoreGuard` across an `.await`, so they are genuinely `Send` — no
/// single-threaded-executor `unsafe` is needed.
pub type SpawnedTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Spawns the stack's background tasks.
///
/// A value, not a static method, because embassy spawning needs its `Spawner` token
/// (which tokio's global spawn doesn't) — so the stack is handed one at construction.
/// Reached via[`Runtime::Spawner`].
pub trait Spawn: Send + Sync + 'static {
    /// Spawn a detached background task.
    fn spawn(&self, task: SpawnedTask);

    /// Stop every task spawned through this spawner and wait for them to finish, so a
    /// replaced host stack provably stops before its successor runs. A no-op on
    /// executors that cannot cancel tasks (embassy).
    fn shutdown(&self) -> impl Future<Output = ()> + Send;
}

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

    /// Spawns the stack's background tasks; see [`Spawn`].
    type Spawner: Spawn;

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
    type Spawner = TokioSpawner;

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

/// The tokio spawner: tasks go into a `JoinSet` so a replaced stack can abort them.
#[derive(Default)]
pub struct TokioSpawner {
    tasks: parking_lot::Mutex<tokio::task::JoinSet<()>>,
}

impl Spawn for TokioSpawner {
    fn spawn(&self, task: SpawnedTask) {
        let mut tasks = self.tasks.lock();

        // A completed task's cell lingers until reaped; drain here so the set tracks live
        // tasks instead of growing by one dead entry per spawn.
        while let Some(result) = tasks.try_join_next() {
            if let Err(e) = result
                && e.is_panic()
            {
                tracing::error!("Background task panicked: {e}");
            }
        }

        tasks.spawn(task);
    }

    async fn shutdown(&self) {
        let mut tasks = core::mem::take(&mut *self.tasks.lock());
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}
