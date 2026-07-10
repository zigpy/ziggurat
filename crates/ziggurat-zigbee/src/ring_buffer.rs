//! A fixed-capacity ring holding the last values pushed, stored inline (no heap).

/// The last `N` values pushed, overwriting the oldest once full.
#[derive(Debug, Clone, Copy)]
pub struct RingBuffer<T, const N: usize> {
    values: [T; N],
    /// Valid values, saturating at `N`.
    len: u8,
    /// The slot the next push overwrites (the oldest once wrapped).
    next: u8,
}

impl<T: Copy + Default, const N: usize> Default for RingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> RingBuffer<T, N> {
    pub fn new() -> Self {
        const { assert!(N > 0 && N <= u8::MAX as usize) };
        Self {
            values: [T::default(); N],
            len: 0,
            next: 0,
        }
    }

    pub fn push(&mut self, value: T) {
        self.values[usize::from(self.next)] = value;
        self.next = (self.next + 1) % N as u8;
        self.len = core::cmp::min(self.len + 1, N as u8);
    }

    pub const fn clear(&mut self) {
        self.len = 0;
        self.next = 0;
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn is_full(&self) -> bool {
        self.len as usize == N
    }

    /// The stored values: insertion-ordered until the ring wraps, rotated after.
    pub fn values(&self) -> &[T] {
        &self.values[..self.len()]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ring_buffer() {
        let mut ring: RingBuffer<u8, 3> = RingBuffer::new();
        assert!(ring.is_empty());
        assert!(!ring.is_full());
        assert_eq!(ring.values(), &[]);

        ring.push(1);
        ring.push(2);
        assert_eq!(ring.len(), 2);
        assert!(!ring.is_full());
        assert_eq!(ring.values(), &[1, 2]);

        ring.push(3);
        assert!(ring.is_full());
        assert_eq!(ring.values(), &[1, 2, 3]);

        // Wrapping overwrites the oldest value; the slice is rotated
        ring.push(4);
        assert!(ring.is_full());
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.values(), &[4, 2, 3]);

        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(ring.values(), &[]);
    }
}
