//! Random values drawn from the runtime's byte source.

use crate::runtime::Runtime;

/// A uniform `f32` in `[0, 1)`, for jitter scaling.
pub fn random_f32<R: Runtime>() -> f32 {
    // 24-bit mantissa worth of entropy mapped into [0, 1)
    (u32::from_le_bytes(random_array::<R, 4>()) >> 8) as f32 / (1u32 << 24) as f32
}

/// A uniform `u8`, for the initial APS counter.
pub fn random_u8<R: Runtime>() -> u8 {
    random_array::<R, 1>()[0]
}

/// A uniform `u16`, for stochastic address allocation.
pub fn random_u16<R: Runtime>() -> u16 {
    u16::from_le_bytes(random_array::<R, 2>())
}

/// `N` random bytes, for key material.
pub fn random_array<R: Runtime, const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    R::fill_random(&mut bytes);
    bytes
}
