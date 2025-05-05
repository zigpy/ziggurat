pub use arbitrary_int::{u1, u2, u3, u4, u5, u6, u7};
pub use bitvec;
use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;
pub use wire_format_derive::zigbee_bytes;

#[derive(Debug, thiserror::Error)]
pub enum FromBytesError {
    #[error("Got invalid discriminant {got} while deserializing enum {ty}")]
    InvalidDiscriminant { ty: &'static str, got: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum ToBytesError {
    // #[error("")]
}

pub trait ZigbeeBytes {
    fn needed_bits(&self) -> usize;
    fn write_zigbee_bytes(&self, writer: &mut BitWriter) -> Result<(), ToBytesError>;
    fn read_zigbee_bytes(reader: &mut BitReader) -> Result<Self, FromBytesError>
    where
        Self: Sized;

    fn to_zigbee_bytes(&self) -> Result<Vec<u8>, ToBytesError> {
        let mut buffer = vec![0u8; 100];
        let mut writer = BitWriter::from(buffer.as_mut_slice());
        self.write_zigbee_bytes(&mut writer)?;
        Ok(buffer)
    }

    fn from_zigbee_bytes(bytes: &[u8]) -> Result<Self, FromBytesError>
    where
        Self: Sized,
    {
        let mut reader = BitReader::from(bytes);
        Self::read_zigbee_bytes(&mut reader)
    }
}

macro_rules! impl_zigbeebytes_for_UInt {
    ($base_type:ty, $write_method:ident, $read_method: ident) => {
        impl<const N: usize> ZigbeeBytes for arbitrary_int::UInt<$base_type, N> {
            fn needed_bits(&self) -> usize {
                Self::BITS
            }

            fn write_zigbee_bytes(&self, writer: &mut BitWriter) -> Result<(), ToBytesError> {
                writer.$write_method(self.needed_bits(), self.value());
                Ok(())
            }

            fn read_zigbee_bytes(reader: &mut BitReader) -> Result<Self, FromBytesError>
            where
                Self: Sized,
            {
                let value = reader.$read_method(Self::BITS);
                Ok(Self::new(value))
            }
        }
    };
}

impl_zigbeebytes_for_UInt! {u8, write_u8, read_u8}
impl_zigbeebytes_for_UInt! {u16, write_u16, read_u16}
impl_zigbeebytes_for_UInt! {u32, write_u32, read_u32}
impl_zigbeebytes_for_UInt! {u64, write_u64, read_u64}

macro_rules! impl_zigbeebytes_for_core_int {
    ($type:ty, $write_method:ident, $read_method:ident, $bits:literal) => {
        impl ZigbeeBytes for $type {
            fn needed_bits(&self) -> usize {
                const { assert!(core::mem::size_of::<Self>() * 8 == $bits) }
                core::mem::size_of::<Self>() * 8
            }

            fn write_zigbee_bytes(&self, writer: &mut BitWriter) -> Result<(), ToBytesError> {
                writer.$write_method($bits, *self);
                Ok(())
            }

            fn read_zigbee_bytes(reader: &mut BitReader) -> Result<Self, FromBytesError>
            where
                Self: Sized,
            {
                Ok(reader.$read_method($bits))
            }
        }
    };
}

impl_zigbeebytes_for_core_int! {u8, write_u8, read_u8, 8}
impl_zigbeebytes_for_core_int! {u16, write_u16, read_u16, 16}
impl_zigbeebytes_for_core_int! {u32, write_u32, read_u32, 32}
impl_zigbeebytes_for_core_int! {u64, write_u64, read_u64, 64}

impl ZigbeeBytes for bool {
    fn needed_bits(&self) -> usize {
        1
    }

    fn write_zigbee_bytes(&self, writer: &mut BitWriter) -> Result<(), ToBytesError> {
        writer.write_bit(*self);
        Ok(())
    }

    fn read_zigbee_bytes(reader: &mut BitReader) -> Result<Self, FromBytesError>
    where
        Self: Sized,
    {
        Ok(reader.read_bit())
    }
}

impl<const N: usize, T: ZigbeeBytes + Sized> ZigbeeBytes for [T; N] {
    fn needed_bits(&self) -> usize {
        self.iter().map(|item| item.needed_bits()).sum()
    }

    fn write_zigbee_bytes(&self, writer: &mut BitWriter) -> Result<(), ToBytesError> {
        for element in self.iter() {
            element.write_zigbee_bytes(writer)?;
        }
        Ok(())
    }
    fn read_zigbee_bytes(reader: &mut BitReader) -> Result<Self, FromBytesError>
    where
        Self: Sized,
    {
        let mut res = Vec::new();
        for _ in 0..N {
            res.push(T::read_zigbee_bytes(reader)?);
        }

        res.try_into()
            .map_err(|_| unreachable!("for loop ensures vec length matches array's"))
    }
}

impl<T: ZigbeeBytes> ZigbeeBytes for Vec<T> {
    fn needed_bits(&self) -> usize {
        const SIZE_OF_LEN: usize = 1;
        SIZE_OF_LEN + self.iter().map(|item| item.needed_bits()).sum::<usize>()
    }

    fn write_zigbee_bytes(&self, writer: &mut BitWriter) -> Result<(), ToBytesError> {
        (self.len() as u8).write_zigbee_bytes(writer)?;
        for element in self.iter() {
            element.write_zigbee_bytes(writer)?;
        }
        Ok(())
    }

    fn read_zigbee_bytes(reader: &mut BitReader) -> Result<Self, FromBytesError>
    where
        Self: Sized,
    {
        let len = u8::read_zigbee_bytes(reader)?;
        let mut res = Vec::with_capacity(len as usize);
        for _ in 0..len {
            res.push(T::read_zigbee_bytes(reader)?);
        }
        Ok(res)
    }
}

// For now these use owned fixed size arrays. In the future we might want to
// borrow those, that could help minimize stack usage on embedded.
pub struct BitWriter<'a> {
    pos: usize,
    buf: &'a mut BitSlice<u8, Lsb0>,
}
pub struct BitReader<'a> {
    pos: usize,
    buf: &'a BitSlice<u8, Lsb0>,
}

impl<'a> BitReader<'a> {
    pub fn skip(&mut self, n_bits: usize) {
        self.pos += n_bits;
    }
    fn read_bit(&mut self) -> bool {
        let res = self
            .buf
            .get(self.pos)
            .expect("should not call read after reader is at end of buffer");
        self.pos += 1;
        *res
    }
    fn read_u8(&mut self, n_bits: usize) -> u8 {
        let mut res = 0u8;
        let res_bits = BitSlice::<_, Lsb0>::from_element_mut(&mut res);
        res_bits.copy_from_bitslice(&self.buf[self.pos..self.pos + n_bits]);
        self.pos += n_bits;
        res
    }
    fn read_u16(&mut self, n_bits: usize) -> u16 {
        let mut res = [0u8; 2];
        let res_bits = BitSlice::<_, Lsb0>::from_slice_mut(&mut res);
        res_bits.copy_from_bitslice(&self.buf[self.pos..self.pos + n_bits]);
        self.pos += n_bits;
        u16::from_le_bytes(res)
    }
    fn read_u32(&mut self, n_bits: usize) -> u32 {
        let mut res = [0u8; 4];
        let res_bits = BitSlice::<_, Lsb0>::from_slice_mut(&mut res);
        res_bits.copy_from_bitslice(&self.buf[self.pos..self.pos + n_bits]);
        self.pos += n_bits;
        u32::from_le_bytes(res)
    }
    fn read_u64(&mut self, n_bits: usize) -> u64 {
        let mut res = [0u8; 8];
        let res_bits = BitSlice::<_, Lsb0>::from_slice_mut(&mut res);
        res_bits.copy_from_bitslice(&self.buf[self.pos..self.pos + n_bits]);
        self.pos += n_bits;
        u64::from_le_bytes(res)
    }
}

impl<'a> From<&'a [u8]> for BitReader<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self {
            pos: 0,
            buf: BitSlice::from_slice(bytes),
        }
    }
}

impl<'a> BitWriter<'a> {
    pub fn skip(&mut self, n_bits: usize) {
        self.pos += n_bits;
    }
    fn write_bit(&mut self, bit: bool) {
        self.buf.set(self.pos, bit);
        self.pos += 1;
    }
    fn write_u8(&mut self, n_bits: usize, val: u8) {
        let val = BitSlice::<_, Lsb0>::from_element(&val);
        self.buf[self.pos..self.pos + n_bits].copy_from_bitslice(val);
        self.pos += n_bits;
    }
    fn write_u16(&mut self, n_bits: usize, val: u16) {
        let val = val.to_le_bytes();
        let val = BitSlice::<_, Lsb0>::from_slice(&val);
        self.buf[self.pos..self.pos + n_bits].copy_from_bitslice(val);
        self.pos += n_bits;
    }
    fn write_u32(&mut self, n_bits: usize, val: u32) {
        let val = val.to_le_bytes();
        let val = BitSlice::<_, Lsb0>::from_slice(&val);
        self.buf[self.pos..self.pos + n_bits].copy_from_bitslice(val);
        self.pos += n_bits;
    }
    fn write_u64(&mut self, n_bits: usize, val: u64) {
        let val = val.to_le_bytes();
        let val = BitSlice::<_, Lsb0>::from_slice(&val);
        self.buf[self.pos..self.pos + n_bits].copy_from_bitslice(val);
        self.pos += n_bits;
    }
}

impl<'a> From<&'a mut [u8]> for BitWriter<'a> {
    fn from(buf: &'a mut [u8]) -> Self {
        Self {
            pos: 0,
            buf: BitSlice::from_slice_mut(buf),
        }
    }
}
