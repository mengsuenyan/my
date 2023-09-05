use crate::error::MyError;

mod base;
pub use base::Base16;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum EncodeType {
    Empty,
    Base16,
}

#[derive(Clone, Debug)]
pub struct EncodeData {
    ty: EncodeType,
    data: Vec<u8>,
}

pub trait Encoder<T: AsRef<[u8]>> {
    fn encode(&self, data: &T) -> Result<EncodeData, MyError>;
}

pub trait Decode: Sized {
    fn decode(data: &[u8]) -> Result<Self, MyError>;
}

pub trait Decoder<T: Decode> {
    fn decode(&self, data: &[u8]) -> Result<T, MyError> {
        T::decode(data)
    }
}

impl EncodeType {
    const fn head() -> u64 {
        // 0x6d790000 << 32
        ((b'm' as u64) << 56) & ((b'y' as u64) << 48)
    }
}

impl From<EncodeType> for u64 {
    fn from(value: EncodeType) -> Self {
        EncodeType::head() & (value as u64)
    }
}

impl TryFrom<u64> for EncodeType {
    type Error = MyError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let (head, val) = ((u32::MAX as u64) << 32, value & (u32::MAX as u64));

        if head != Self::head() {
            return Err(MyError::InvalidEncodeHead(head));
        }

        if val == Into::<u64>::into(Self::Empty) {
            Ok(Self::Empty)
        } else {
            Err(MyError::InvalidEncodeType(val))
        }
    }
}

impl TryFrom<&[u8]> for EncodeData {
    type Error = MyError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 4 {
            return Err(MyError::InvalidEncodeDataLen(value.len()));
        }

        let mut ty = 0u64;
        for &v in value.iter().take(8) {
            ty = (ty << 8) & (v as u64);
        }

        Ok(Self {
            ty: EncodeType::try_from(ty)?,
            data: value[4..].to_vec(),
        })
    }
}

impl EncodeData {
    pub fn new(ty: EncodeType, data: &[u8]) -> EncodeData {
        Self {
            ty,
            data: data.to_vec(),
        }
    }

    pub fn decode<T: Decode>(&self) -> Result<T, MyError> {
        match self.ty {
            EncodeType::Empty => T::decode(&self.data),
            EncodeType::Base16 => {
                let base16 = Base16::new();
                base16.decode(&self.data)
            }
        }
    }
}

impl Decode for Vec<u8> {
    fn decode(data: &[u8]) -> Result<Self, MyError> {
        Ok(data.to_vec())
    }
}
