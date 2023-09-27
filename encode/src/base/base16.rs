use crate::{Decode, Encode, EncodeError};
use std::io::{Read, Write};

#[derive(Clone)]
pub struct Base16 {
    buf: Vec<u8>,
}

impl Base16 {
    pub fn new() -> Self {
        Self::with_capacity(128)
    }

    /// 指定缓存大小
    pub fn with_capacity(cap: usize) -> Self {
        let mut x = vec![];
        x.resize(cap.max(128), 0);
        Self { buf: x }
    }
}

impl Default for Base16 {
    fn default() -> Self {
        Self::new()
    }
}

impl Base16 {
    const BASE16_STD: [u8; 16] = [
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E',
        b'F',
    ];
}

impl Encode for Base16 {
    fn encode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError> {
        let mut ilen = 0;

        loop {
            let l = in_data.read(self.buf.as_mut_slice())?;

            if l == 0 {
                break;
            }

            for &d in self.buf.iter().take(l) {
                let o = [
                    Self::BASE16_STD[(d >> 4) as usize],
                    Self::BASE16_STD[(d & 0xf) as usize],
                ];
                out_data.write_all(&o)?;
            }

            ilen += l;
        }

        out_data.flush()?;
        Ok((ilen, ilen << 1))
    }
}

impl Decode for Base16 {
    fn decode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError> {
        let (mut ilen, mut num) = (0, 0);

        loop {
            let l = in_data.read(self.buf.as_mut_slice())?;

            if l == 0 {
                break;
            }

            for d in self.buf.iter().take(l) {
                let x = match d {
                    x if x.is_ascii_digit() => x - b'0',
                    x if (b'a'..=b'f').contains(x) => 10 + x - b'a',
                    x if (b'A'..=b'F').contains(x) => 10 + x - b'A',
                    _ => {
                        return Err(EncodeError::InvalidBaseCodeInDec(char::from(*d)));
                    }
                };
                num = (num << 4) | x;
                if ilen & 1 == 1 {
                    out_data.write_all(&[num])?;
                } else {
                    num = x;
                }

                ilen += 1;
            }
        }

        if ilen & 1 != 0 {
            Err(EncodeError::InvalidLenInDec(ilen))
        } else {
            out_data.flush()?;
            Ok((ilen, ilen >> 1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Base16;
    use crate::{Decode, Encode};

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
        let mut base16 = Base16::new();
        let mut buf = vec![];
        for (idx, (case, tgt)) in CASES.iter().enumerate() {
            buf.clear();
            let enc = base16.encode(&mut case.as_slice(), &mut buf).unwrap();
            assert_eq!(enc.0 << 1, enc.1, "case {idx} failed");
            assert_eq!(buf, tgt, "case {idx} failed");
        }
    }

    #[test]
    fn base16_decode() {
        let mut base16 = Base16::new();
        let mut buf = vec![];
        for (idx, (tgt, case)) in CASES.iter().enumerate() {
            buf.clear();
            let enc = base16.decode(&mut case.as_slice(), &mut buf).unwrap();
            assert_eq!(enc.0, enc.1 << 1, "case {idx} failed");
            assert_eq!(buf, tgt, "case {idx} failed");
        }
    }
}
