//! Randomness crate.

/// A uniform `f32` in `[0, 1)`, for jitter scaling.
pub fn random_f32() -> f32 {
    let mut bytes = [0u8; 4];
    fill_bytes(&mut bytes);
    // 24-bit mantissa worth of entropy mapped into [0, 1)
    (u32::from_le_bytes(bytes) >> 8) as f32 / (1u32 << 24) as f32
}

/// A uniform `u16`, for stochastic address allocation.
pub fn random_u16() -> u16 {
    let mut bytes = [0u8; 2];
    fill_bytes(&mut bytes);
    u16::from_le_bytes(bytes)
}

/// `N` random bytes, for key material.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    fill_bytes(&mut bytes);
    bytes
}

#[cfg(feature = "tokio")]
fn fill_bytes(buf: &mut [u8]) {
    use rand::RngExt;
    rand::rng().fill(buf);
}

#[cfg(all(feature = "embassy", not(feature = "tokio")))]
pub use embassy_rng::{fill_bytes, install};

#[cfg(all(feature = "embassy", not(feature = "tokio")))]
mod embassy_rng {
    use crate::sync::Mutex;
    use alloc::boxed::Box;

    type FillFn = Box<dyn FnMut(&mut [u8]) + Send>;

    static FILL: Mutex<Option<FillFn>> = Mutex::new(None);

    /// Install the byte source. The MCU binary backs this with the SoC hardware RNG.
    pub fn install(fill: FillFn) {
        *FILL.lock() = Some(fill);
    }

    pub fn fill_bytes(buf: &mut [u8]) {
        let mut guard = FILL.lock();
        let fill = guard.as_mut().expect("rng::install was never called");
        fill(buf);
    }
}
