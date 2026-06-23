//! The synchronization primitives the stack rests on: a blocking [`Mutex`] and an async
//! [`Notify`].

pub use parking_lot::{Mutex, MutexGuard};
pub use tokio::sync::Notify;

/// An async mutex, for the few places a guard is held across an `.await` (the radio
/// stream and reset receivers). Distinct from the blocking [`Mutex`], which must never
/// span a yield; reach for this only when the guard genuinely outlives an await point.
pub use tokio::sync::Mutex as AsyncMutex;
