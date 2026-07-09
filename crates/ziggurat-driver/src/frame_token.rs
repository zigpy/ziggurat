//! The frame-token budget: bounds how many frames the stack may hold alive at once.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Total frame tokens, set once at stack construction. 0 means unbounded (a host
/// with the system allocator).
static TOTAL_TOKENS: AtomicUsize = AtomicUsize::new(0);
static CRITICAL_RESERVE: AtomicUsize = AtomicUsize::new(0);
static FORWARDING_RESERVE: AtomicUsize = AtomicUsize::new(0);
static USED_TOKENS: AtomicUsize = AtomicUsize::new(0);

/// Which tier of the frame budget admits a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    /// A frame we originate on the host's behalf: refused first under pressure, the
    /// host is told and can pace itself.
    Host,
    /// A transit frame relayed for another device: dropping one degrades the mesh but
    /// the originator retries end-to-end.
    Forwarding,
    /// Stack machinery the mesh cannot function without: joins, APS acks, NWK
    /// commands, indirect deliveries. Admitted until the budget is truly exhausted.
    Critical,
}

/// One admitted frame's slice of the budget. Not cloneable; dropping it returns the
/// token. Stored inside whichever queue currently owns the frame.
#[derive(Debug)]
pub struct FrameToken(());

impl Drop for FrameToken {
    fn drop(&mut self) {
        USED_TOKENS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Set the token budget and the per-tier reserves. Called once at stack construction,
/// before any token is taken. A `total_tokens` of 0 leaves the budget unbounded.
pub fn set_budget(total_tokens: usize, critical_reserve: usize, forwarding_reserve: usize) {
    TOTAL_TOKENS.store(total_tokens, Ordering::Relaxed);
    CRITICAL_RESERVE.store(critical_reserve, Ordering::Relaxed);
    FORWARDING_RESERVE.store(forwarding_reserve, Ordering::Relaxed);
}

/// Take one frame token, or refuse when the class's tier is full.
pub fn take(class: TrafficClass) -> Option<FrameToken> {
    let total = TOTAL_TOKENS.load(Ordering::Relaxed);

    let limit = if total == 0 {
        usize::MAX
    } else {
        match class {
            TrafficClass::Critical => total,
            TrafficClass::Forwarding => total - CRITICAL_RESERVE.load(Ordering::Relaxed),
            TrafficClass::Host => {
                total
                    - CRITICAL_RESERVE.load(Ordering::Relaxed)
                    - FORWARDING_RESERVE.load(Ordering::Relaxed)
            }
        }
    };

    if USED_TOKENS.fetch_add(1, Ordering::Relaxed) < limit {
        Some(FrameToken(()))
    } else {
        USED_TOKENS.fetch_sub(1, Ordering::Relaxed);
        None
    }
}

/// Tokens currently held, for diagnostics.
pub fn used() -> usize {
    USED_TOKENS.load(Ordering::Relaxed)
}

/// The total token budget, for diagnostics. 0 means unbounded.
pub fn total() -> usize {
    TOTAL_TOKENS.load(Ordering::Relaxed)
}

// Allocator debug instrumentation below: the platform's heap arena size and the
// tracking allocator's live/peak byte counters, surfaced through `get_diagnostics`.
// Kept only while the memory work is being debugged; it will be removed.

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
