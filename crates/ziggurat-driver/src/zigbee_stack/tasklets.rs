//! Small tasks multiplexed on one executor slot.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use futures::stream::{FuturesUnordered, StreamExt};

use crate::runtime::Runtime;
use crate::sync::{Mutex, Notify};
use ziggurat_phy::RadioPhy;

use super::ZigbeeStack;

type Tasklet = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The inbox of not-yet-started tasklets.
#[derive(Default)]
pub struct Tasklets {
    injected: Mutex<Vec<Tasklet>>,
    wake: Notify,
}

impl Tasklets {
    /// Hand a tasklet to the runner. The future must own its stack reference (capture
    /// an `Arc`); it starts on the runner's next pass.
    pub fn push(&self, tasklet: impl Future<Output = ()> + Send + 'static) {
        self.injected.lock().push(Box::pin(tasklet));
        self.wake.notify_one();
    }
}

impl core::fmt::Debug for Tasklets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tasklets")
            .field("injected", &self.injected.lock().len())
            .finish()
    }
}

impl<P: RadioPhy, R: Runtime> ZigbeeStack<P, R> {
    /// Drive every in-flight tasklet, multiplexed on this one task.
    pub(super) async fn tasklet_task(&self) {
        let mut running: FuturesUnordered<Tasklet> = FuturesUnordered::new();

        loop {
            running.extend(self.tasklets.injected.lock().drain(..));

            // `next()` on an empty set is `None` immediately, not pending: park on the
            // inbox wake instead of spinning.
            if running.is_empty() {
                self.tasklets.wake.notified().await;
                continue;
            }

            // Wake on a tasklet finishing or a new injection. Dropping the losing
            // `next()` future drops only the poll adapter, never the tasklets.
            let injected = core::pin::pin!(self.tasklets.wake.notified());
            let _ = futures::future::select(running.next(), injected).await;
        }
    }
}
