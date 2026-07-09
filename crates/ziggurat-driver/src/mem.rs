//! Firmware heap info, reported by the platform's allocator and read by the stack to
//! bound its heap use. A host with the system allocator reports no arena and is unbounded.

use core::sync::atomic::{AtomicUsize, Ordering};

static HEAP_ARENA_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Called once by the platform at startup, before the stack runs.
pub fn set_heap_arena(bytes: usize) {
    HEAP_ARENA_BYTES.store(bytes, Ordering::Relaxed);
}

/// The heap arena size, or 0 if unknown (an unbounded host allocator).
pub fn heap_arena() -> usize {
    HEAP_ARENA_BYTES.load(Ordering::Relaxed)
}

pub fn record_alloc(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

pub fn record_dealloc(bytes: usize) {
    LIVE_BYTES.fetch_sub(bytes, Ordering::Relaxed);
}

pub fn live() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

pub fn peak() -> usize {
    PEAK_BYTES.load(Ordering::Relaxed)
}
