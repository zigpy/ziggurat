use ziggurat_ieee_802154::types::{Eui64, Key};

use super::*;

const PERSIST_INTERVAL: u32 = 100;

fn security() -> ApsSecurity {
    ApsSecurity::new(
        Key([0; 16]),
        Eui64::from_be_bytes([0; 8]),
        None,
        PERSIST_INTERVAL,
    )
}

/// Encrypt `frames` frames, as far as the counter is concerned.
fn advance(security: &mut ApsSecurity, frames: u32) {
    for _ in 0..frames {
        security.next_outgoing_frame_counter();
    }
}

#[test]
fn test_counter_is_persisted_once_per_interval() {
    let mut security = security();

    advance(&mut security, PERSIST_INTERVAL - 1);
    assert_eq!(security.take_counter_to_persist(), None);

    advance(&mut security, 1);
    assert_eq!(security.take_counter_to_persist(), Some(PERSIST_INTERVAL));
    assert_eq!(security.take_counter_to_persist(), None);
}

// A caller that did not ask in time still gets the value, and the next one is a full
// interval after it.
#[test]
fn test_missed_call_persists_the_counter_at_the_next_one() {
    let mut security = security();

    advance(&mut security, PERSIST_INTERVAL + 30);
    assert_eq!(
        security.take_counter_to_persist(),
        Some(PERSIST_INTERVAL + 30)
    );

    advance(&mut security, PERSIST_INTERVAL - 1);
    assert_eq!(security.take_counter_to_persist(), None);
}

// The restored value may be one the client never stored, such as its own margin on top
// of what it had. The first frame after it tells the client where the counter is.
#[test]
fn test_restored_counter_is_persisted_at_the_first_frame() {
    let mut security = security();
    security.restore_outgoing_frame_counter(12_345);

    advance(&mut security, 1);
    assert_eq!(security.take_counter_to_persist(), Some(12_346));
}
