use crate::{Decode, Encode, EncodeError};
use std::io::{Read, Write};

#[derive(Default)]
pub struct Base58;

impl Base58 {
    const BASE58_STD: [u8; 58] = [
        b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F',
        b'G', b'H', b'J', b'K', b'L', b'M', b'N', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W',
        b'X', b'Y', b'Z', b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'm',
        b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',
    ];

    const MAP_BASE58: [i8; 256] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1, -1, 9, 10, 11, 12, 13, 14,
        15, 16, -1, 17, 18, 19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1,
        -1, -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48, 49, 50, 51,
        52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1,
    ];

    pub fn new() -> Self {
        Base58
    }
}

impl Encode for Base58 {
    fn encode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError> {
        let mut data = vec![];
        let ilen = in_data.read_to_end(&mut data)?;

        let (mut leading_zeros, mut len) = (0, 0);
        for &ele in data.iter() {
            if ele == 0 {
                leading_zeros += 1;
            } else {
                break;
            }
        }

        let size = (data.len() - leading_zeros) * 138 / 100 + 1;
        let mut b58 = vec![];
        b58.resize(size, 0);

        for &ele in data.iter().skip(leading_zeros) {
            let (mut carry, mut i) = (ele as usize, 0);

            for x in b58.iter_mut().rev() {
                if carry == 0 && i >= len {
                    break;
                }

                carry += 256 * (*x as usize);
                *x = (carry % 58) as u8;

                carry /= 58;

                i += 1;
            }

            len = i;
        }

        let mut itr = b58.iter().skip(size - len);

        for _ in 0..leading_zeros {
            out_data.write_all(&[b'1'])?;
        }

        let mut olen = leading_zeros;

        for &d in &mut itr {
            out_data.write_all(&[Base58::BASE58_STD[d as usize]])?;
            olen += 1;
        }

        Ok((ilen, olen))
    }
}

impl Decode for Base58 {
    fn decode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError> {
        let mut data = vec![];
        let ilen = in_data.read_to_end(&mut data)?;

        let mut len = 0;
        let leading_zeros = data.iter().take_while(|&&x| x == b'1').count();
        let mut b256 = Vec::new();
        b256.resize((data.len() - leading_zeros) * 733 / 1000 + 1, 0);

        for &ele in data.iter().skip(leading_zeros) {
            let mut carry = Self::MAP_BASE58[ele as usize] as i32;
            if carry == -1 {
                return Err(EncodeError::InvalidBaseCodeInDec(char::from(ele)));
            }

            let mut i = 0;
            for x in b256.iter_mut().rev() {
                if carry == 0 && i >= len {
                    break;
                }

                carry += 58 * (*x as i32);
                *x = (carry % 256) as u8;
                carry /= 256;
                i += 1;
            }
            len = i;
        }

        for _ in 0..leading_zeros {
            out_data.write_all(&[0])?;
        }

        let olen = b256.len();
        out_data.write_all(&b256[(olen - len)..])?;

        Ok((ilen, len + leading_zeros))
    }
}

#[cfg(test)]
mod tests {
    use crate::base::base58::Base58;
    use crate::{Decode, Encode};

    #[test]
    fn base58() {
        let cases = [
            (b"\0abc".to_vec(), "1ZiCa"),
            (b"\0\0abc".to_vec(), "11ZiCa"),
            (b"\0\0\0abc".to_vec(), "111ZiCa"),
            (b"\0\0\0\0abc".to_vec(), "1111ZiCa"),
            (b"1234598760".to_vec(), "3mJr7AoUXx2Wqd"),
            (b"abc".to_vec(), "ZiCa"),
            (b"".to_vec(), ""),
            (vec![32], "Z"),
            (vec![45], "n"),
            (vec![48], "q"),
            (vec![49], "r"),
            (vec![57], "z"),
            ([49, 49].to_vec(), "4k8"),
            ([45, 49].to_vec(), "4SU"),
            (
                b"abcdefghijklmnopqrstuvwxyz".to_vec(),
                "3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f",
            ),
        ];

        for (i, (case, std)) in cases.into_iter().enumerate() {
            let (mut buf, mut base) = (vec![], Base58::new());
            let (ilen, olen) = base.encode(&mut case.as_slice(), &mut buf).unwrap();

            assert_eq!(ilen, case.len(), "case {i} encode failed");
            assert_eq!(olen, buf.len(), "case {i} encode failed");
            assert_eq!(buf, std.as_bytes(), "case {i} encode failed");

            buf.clear();
            let (ilen, olen) = base.decode(&mut std.as_bytes(), &mut buf).unwrap();
            assert_eq!(ilen, std.len(), "case {i} decode failed");
            assert_eq!(olen, buf.len(), "case {i} decode failed");
            assert_eq!(buf, case, "case {i} decode failed");
        }
    }
}
