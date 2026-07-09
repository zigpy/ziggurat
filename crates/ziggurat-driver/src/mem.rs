//! Firmware memory info, reported once by the platform's allocator.
use core::sync::atomic::{AtomicUsize, Ordering};

/// Total heap arena in bytes, or 0 when the platform never reported one.
static HEAP_ARENA_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Record the size of the heap the allocator manages. The platform calls this once at
/// startup, before the stack runs.
pub fn set_heap_arena(bytes: usize) {
    HEAP_ARENA_BYTES.store(bytes, Ordering::Relaxed);
}

/// The heap arena size in bytes, or 0 if unknown (an unbounded host allocator).
pub fn heap_arena() -> usize {
    HEAP_ARENA_BYTES.load(Ordering::Relaxed)
}
