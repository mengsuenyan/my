use super::{Decode, Decoder, EncodeData, EncodeType, Encoder};
use crate::error::MyError;

const BASE16_STD: [u8; 16] = [
    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F',
];

pub struct Base16;

impl Base16 {
    pub fn new() -> Self {
        Self
    }
}

impl<T: AsRef<[u8]>> Encoder<T> for Base16 {
    // 大端序
    fn encode(&self, data: &T) -> Result<EncodeData, MyError> {
        let data = data.as_ref();
        let mut buf = Vec::with_capacity(data.len() << 1);
        for &ele in data.iter() {
            buf.push(BASE16_STD[ele as usize >> 4]);
            buf.push(BASE16_STD[ele as usize & 0xf]);
        }

        Ok(EncodeData {
            ty: EncodeType::Base16,
            data: buf,
        })
    }
}

impl<T: Decode> Decoder<T> for Base16 {
    fn decode(&self, data: &[u8]) -> Result<T, MyError> {
        if (data.len() & 1) != 0 {
            return Err(MyError::InvalidEncodeDataLen(data.len()));
        }
        let mut buf = Vec::with_capacity(data.len() >> 1);

        for ((hi_idx, &hi), (lo_idx, &lo)) in data
            .iter()
            .enumerate()
            .step_by(2)
            .zip(data.iter().enumerate().skip(1).step_by(2))
        {
            let hi = if hi >= b'0' && hi <= b'9' {
                hi - b'0'
            } else if hi >= b'A' && lo <= b'F' {
                10 + hi - b'A'
            } else {
                return Err(MyError::InvaidEncodeData {
                    idx: hi_idx,
                    data: hi,
                });
            };
            let lo = if lo >= b'0' && lo <= b'9' {
                lo - b'0'
            } else if lo >= b'A' && lo <= b'F' {
                10 + lo - b'A'
            } else {
                return Err(MyError::InvaidEncodeData {
                    idx: lo_idx,
                    data: lo,
                });
            };

            buf.push((hi << 4) | lo)
        }

        T::decode(&buf)
    }
}

#[cfg(test)]
mod tests {
    use crate::encode::{Decoder, Encoder};

    use super::Base16;

    const CASES: [([u8; 4], [u8; 8]); 3] = [
        (
            [0x9au8, 0x3f, 0x46, 0x77],
            [b'9', b'A', b'3', b'F', b'4', b'6', b'7', b'7'],
        ),
        (
            [0x33, 0x8f, 0xd0, 0x54],
            [b'3', b'3', b'8', b'F', b'D', b'0', b'5', b'4'],
        ),
        (
            [0x4d, 0x43, 0x09, 0xda],
            [b'4', b'D', b'4', b'3', b'0', b'9', b'D', b'A'],
        ),
    ];

    #[test]
    fn base16_encode() {
        let base16 = Base16::new();
        for (idx, case) in CASES.iter().enumerate() {
            let enc = base16.encode(&case.0).unwrap();
            assert_eq!(enc.data, case.1, "case {idx} failed");
        }
    }

    #[test]
    fn base16_decode() {
        let base16 = Base16::new();
        for (idx, case) in CASES.iter().enumerate() {
            let dec: Vec<u8> = base16.decode(&case.1).unwrap();
            assert_eq!(dec, case.0, "case {idx} failed");
        }
    }
}
