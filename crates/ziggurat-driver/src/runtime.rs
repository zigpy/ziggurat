//! Async runtime abstraction layer.

use alloc::boxed::Box;
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

#[cfg(feature = "tokio")]
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
#[cfg(feature = "tokio")]
#[derive(Debug, Clone, Copy)]
pub struct TokioRuntime;

#[cfg(feature = "tokio")]
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
#[cfg(feature = "tokio")]
#[derive(Default)]
pub struct TokioSpawner {
    tasks: parking_lot::Mutex<tokio::task::JoinSet<()>>,
}

#[cfg(feature = "tokio")]
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

/// The embassy runtime adapter. Drives the MCU directly; host-runnable through
/// `embassy-host` (`arch-std`) so it can stand in for tokio in tests.
#[cfg(feature = "embassy")]
pub use embassy_impl::{EmbassyRuntime, EmbassySpawner};

#[cfg(feature = "embassy-host")]
pub use embassy_impl::start_embassy_executor;

/// The runtime the stack defaults to when no `R` type parameter is given. Resolves to
/// whichever backend feature is enabled.
#[cfg(feature = "tokio")]
pub type DefaultRuntime = TokioRuntime;
#[cfg(all(feature = "embassy", not(feature = "tokio")))]
pub type DefaultRuntime = EmbassyRuntime;

#[cfg(feature = "embassy")]
mod embassy_impl {
    use super::{RtInstant, Runtime, Spawn, SpawnedTask};
    #[cfg(feature = "embassy-host")]
    use alloc::boxed::Box;
    use core::future::Future;
    use core::ops::Add;
    use core::time::Duration;

    const fn to_embassy(duration: Duration) -> embassy_time::Duration {
        embassy_time::Duration::from_micros(duration.as_micros() as u64)
    }

    const fn from_embassy(duration: embassy_time::Duration) -> Duration {
        Duration::from_micros(duration.as_micros())
    }

    /// Wraps `embassy_time::Instant` so the trait's `core::time::Duration` arithmetic
    /// works against embassy's own `Duration` type.
    #[derive(Copy, Clone)]
    pub struct EmbassyInstant(embassy_time::Instant);

    impl Add<Duration> for EmbassyInstant {
        type Output = Self;

        fn add(self, rhs: Duration) -> Self {
            Self(self.0 + to_embassy(rhs))
        }
    }

    impl RtInstant for EmbassyInstant {
        fn saturating_duration_since(self, earlier: Self) -> Duration {
            from_embassy(self.0.saturating_duration_since(earlier.0))
        }
    }

    pub struct EmbassyRuntime;

    impl Runtime for EmbassyRuntime {
        type Instant = EmbassyInstant;
        type Spawner = EmbassySpawner;

        fn now() -> Self::Instant {
            EmbassyInstant(embassy_time::Instant::now())
        }

        fn sleep(duration: Duration) -> impl Future<Output = ()> + Send {
            embassy_time::Timer::after(to_embassy(duration))
        }

        fn sleep_until(deadline: Self::Instant) -> impl Future<Output = ()> + Send {
            embassy_time::Timer::at(deadline.0)
        }
    }

    /// Each detached task runs in one slot of this fixed pool — embassy has no dynamic
    /// spawn, so the size bounds the stack's concurrent background tasks (long-lived
    /// reactors plus the transient ZDP/indirect/route-request ones).
    #[embassy_executor::task(pool_size = 32)]
    async fn task_runner(task: SpawnedTask) {
        task.await;
    }

    /// Spawns into the embassy executor. Holds a [`SendSpawner`](embassy_executor::SendSpawner)
    /// so it is `Send + Sync`; obtained from the executor at startup.
    #[derive(Clone, Copy)]
    pub struct EmbassySpawner(embassy_executor::SendSpawner);

    impl EmbassySpawner {
        pub const fn new(spawner: embassy_executor::SendSpawner) -> Self {
            Self(spawner)
        }
    }

    impl Spawn for EmbassySpawner {
        fn spawn(&self, task: SpawnedTask) {
            // In embassy-executor 0.10 the pool slot is claimed when the token is built,
            // so exhaustion surfaces here rather than at `spawn`.
            match task_runner(task) {
                Ok(token) => self.0.spawn(token),
                Err(_) => {
                    tracing::error!("embassy task pool exhausted; background task dropped");
                }
            }
        }

        // Embassy cannot cancel spawned tasks; the MCU stack is never replaced, so there
        // is nothing to stop.
        async fn shutdown(&self) {}
    }

    /// Run an embassy `arch-std` executor on a dedicated thread, returning a spawner
    /// for it.
    #[cfg(feature = "embassy-host")]
    pub fn start_embassy_executor(tokio_handle: tokio::runtime::Handle) -> EmbassySpawner {
        use std::sync::mpsc;

        let (tx, rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("embassy-executor".into())
            .spawn(move || {
                // Held for the executor's (and thread's) entire life, so every poll on this
                // thread sees the tokio runtime.
                let _enter = tokio_handle.enter();
                let executor: &'static mut embassy_executor::Executor =
                    Box::leak(Box::new(embassy_executor::Executor::new()));
                executor.run(move |spawner| {
                    let _ = tx.send(spawner.make_send());
                });
            })
            .expect("spawn embassy-executor thread");

        EmbassySpawner::new(rx.recv().expect("embassy executor failed to start"))
    }
}
