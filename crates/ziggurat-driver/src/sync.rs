//! The synchronization primitives the stack rests on: a blocking [`Mutex`] and an async
//! [`Notify`].

pub use parking_lot::{Mutex, MutexGuard};
pub use tokio::sync::Notify;
