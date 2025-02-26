//! ## SHA-3 Derived Function: cSHAKE, KMAC, TupleHash, ParallelHash
//!
//! - [SP 800-184: SHA-3 Derived Function](https://csrc.nist.gov/pubs/sp/800/185/final)
//!

use crate::sha3::SHA3;
use crate::{HashError, XOF};
use std::io::Write;
use std::mem::size_of;

/// `r`指定keccak[c]位率`r = 1600 - c`, 为了方便处理r需是`8`整数倍`R=r/8`
/// ```txt
/// 1. If N = "" and S = "":
/// return SHAKE128(X, L);
/// 2. Else:
/// return KECCAK[256](bytepad(encode_string(N) || encode_string(S), R) || X || 00, L).
/// ```
#[derive(Clone)]
pub struct CSHAKE<const R: usize> {
    start_state: SHA3<R, 0>,
    sha3: SHA3<R, 0>,
    desired_len: usize,
    // function name is empty and custom string is empty
    is_shake: bool,
}

impl<const R: usize> CSHAKE<R> {
    /// `desired_len`: 指定输出哈希字串的字节长度, 记为`L`; <br>
    /// `fuc_name`: NIST定义的基于cSHAKE算法的函数名字, 记为`N`; <br>
    /// `custom`: 自定义位串, 记为`S`; <br>
    ///
    /// 只要cSHAKE两个实例, `N`和`S`任意一个不同, 那么生成的hash值是不相关的.
    pub fn new(desired_len: usize, fuc_name: &[u8], custom: &[u8]) -> Result<Self, HashError> {
        if R > 200 {
            return Err(HashError::Keccak(format!(
                "Invalid SHA3 Keccak rate `{}`, it should be less than 200",
                R
            )));
        }

        let mut sha3 = SHA3::<R, 0>::new();
        if !fuc_name.is_empty() || !custom.is_empty() {
            let _len = Self::byte_pad_for_cshake(fuc_name, custom, R, &mut sha3)?;
            Ok(Self {
                sha3: sha3.clone(),
                start_state: sha3,
                desired_len,
                is_shake: false,
            })
        } else {
            Ok(Self {
                sha3: sha3.clone(),
                start_state: sha3,
                desired_len,
                is_shake: true,
            })
        }
    }

    // 该函数可支持`0 <= x < 2^{2040}`, 实际普通使用不允许这么大的数, 故使用`usize::BITS`即可.
    pub(crate) fn right_encode<W: Write>(x: usize, buf: &mut W) -> Result<usize, HashError> {
        let n = ((usize::BITS + 7 - x.leading_zeros()) as usize / 8).max(1);
        buf.write_all(&x.to_be_bytes()[(size_of::<usize>() - n)..])?;
        buf.write_all(&[n as u8])
            .map(|_| n + 1)
            .map_err(HashError::from)
    }

    fn left_encode<W: Write>(x: usize, buf: &mut W) -> Result<usize, HashError> {
        let n = ((usize::BITS + 7 - x.leading_zeros()) as usize / 8).max(1);
        buf.write_all(&[n as u8])?;
        buf.write_all(&x.to_be_bytes()[(size_of::<usize>() - n)..])
            .map(|_| n + 1)
            .map_err(HashError::from)
    }

    fn encode_string<W: Write>(s: &[u8], buf: &mut W) -> Result<usize, HashError> {
        let len = Self::left_encode(s.len() << 3, buf)?;
        buf.write_all(s)
            .map(|_| s.len() + len)
            .map_err(HashError::from)
    }

    // bytepad(encode_string(N) || encode_string(S), R)
    fn byte_pad_for_cshake<W: Write>(
        fuc_name: &[u8],
        custom: &[u8],
        w: usize,
        buf: &mut W,
    ) -> Result<usize, HashError> {
        let mut len = Self::left_encode(w, buf)?;
        len += Self::encode_string(fuc_name, buf)?;
        len += Self::encode_string(custom, buf)?;
        while len % w != 0 {
            buf.write_all(&[0])?;
            len += 1;
        }

        Ok(len)
    }

    pub(super) fn byte_pad_for_kmac<W: Write>(
        key: &[u8],
        w: usize,
        buf: &mut W,
    ) -> Result<usize, HashError> {
        let mut len = Self::left_encode(w, buf)?;
        len += Self::encode_string(key, buf)?;
        while len % w != 0 {
            buf.write_all(&[0])?;
            len += 1;
        }

        Ok(len)
    }
}

impl<const R: usize> Write for CSHAKE<R> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sha3.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sha3.flush()
    }
}

impl<const R: usize> XOF for CSHAKE<R> {
    const BLOCK_BITS: usize = R << 3;
    const WORD_BITS: usize = R << 3;
    fn desired_len(&self) -> usize {
        self.desired_len
    }

    fn finalize(&mut self) -> Vec<u8> {
        if self.is_shake {
            self.sha3.pad_fips202_xof();
        } else {
            self.sha3.pad_sp800_cshake();
        }

        self.sha3.finalize_inner(self.desired_len).to_vec()
    }

    fn reset(&mut self) {
        self.sha3 = self.start_state.clone();
    }
}

pub type CSHAKE128 = CSHAKE<168>;
pub type CSHAKE256 = CSHAKE<136>;

mod kmac;
pub use kmac::{KMACXof, KMACXof128, KMACXof256, KMAC, KMAC128, KMAC256};

use crate::DigestX;

macro_rules! impl_digestx_for_cshake {
    ($TYPE: tt) => {
        impl<const R: usize> DigestX for $TYPE<R> {
            fn block_bits_x(&self) -> usize {
                Self::BLOCK_BITS
            }

            fn word_bits_x(&self) -> usize {
                Self::WORD_BITS
            }

            fn digest_bits_x(&self) -> usize {
                self.desired_len() << 3
            }

            fn finish_x(&mut self) -> Vec<u8> {
                <Self as XOF>::finalize(self)
            }

            fn reset_x(&mut self) {
                <Self as XOF>::reset(self)
            }
        }
    };

    ($TYPE1: tt, $($TYPE2: tt),+) => {
        impl_digestx_for_cshake!($TYPE1);
        impl_digestx_for_cshake!($($TYPE2),+);
    }
}

impl_digestx_for_cshake!(CSHAKE, KMAC, KMACXof);

#[cfg(test)]
mod tests {
    use crate::cshake::{CSHAKE128, CSHAKE256};
    use crate::sha3::{SHAKE128Wrapper, SHAKE256Wrapper};
    use crate::{Digest, XOF};
    use std::io::Write;

    #[test]
    fn cshake_with_empty_n_s() {
        for i in 195..=205 {
            let msg = format!("{i}").repeat(i);
            let tgt = SHAKE128Wrapper::<16>::digest(msg.as_bytes()).to_vec();
            let mut cshake = CSHAKE128::new(16, &[], &[]).unwrap();
            cshake.write_all(msg.as_bytes()).unwrap();
            let d = cshake.finalize();

            assert_eq!(
                tgt, d,
                "case {i} cshake128 hash not equal to shake128 value"
            );

            let tgt = SHAKE256Wrapper::<16>::digest(msg.as_bytes()).to_vec();
            let mut cshake = CSHAKE256::new(16, &[], &[]).unwrap();
            cshake.write_all(msg.as_bytes()).unwrap();
            let d = cshake.finalize();
            assert_eq!(
                tgt, d,
                "case {i} cshake256 hash not equal to shake256 value"
            );
        }
    }

    #[test]
    fn cshake128() {
        let cases = [
            (
                vec![0, 1, 2, 3],
                32,
                "",
                "Email Signature",
                vec![
                    0xC1, 0xC3, 0x69, 0x25, 0xB6, 0x40, 0x9A, 0x04, 0xF1, 0xB5, 0x04, 0xFC, 0xBC,
                    0xA9, 0xD8, 0x2B, 0x40, 0x17, 0x27, 0x7C, 0xB5, 0xED, 0x2B, 0x20, 0x65, 0xFC,
                    0x1D, 0x38, 0x14, 0xD5, 0xAA, 0xF5,
                ],
            ),
            (
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
                    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
                    0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
                    0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
                    0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81,
                    0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E,
                    0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B,
                    0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
                    0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
                    0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2,
                    0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
                ],
                32,
                "",
                "Email Signature",
                vec![
                    0xC5, 0x22, 0x1D, 0x50, 0xE4, 0xF8, 0x22, 0xD9, 0x6A, 0x2E, 0x88, 0x81, 0xA9,
                    0x61, 0x42, 0x0F, 0x29, 0x4B, 0x7B, 0x24, 0xFE, 0x3D, 0x20, 0x94, 0xBA, 0xED,
                    0x2C, 0x65, 0x24, 0xCC, 0x16, 0x6B,
                ],
            ),
        ];

        for (i, (x, olen, n, s, tgt)) in cases.into_iter().enumerate() {
            let mut cshake = CSHAKE128::new(olen, n.as_bytes(), s.as_bytes()).unwrap();
            cshake.write_all(x.as_slice()).unwrap();

            assert_eq!(tgt, cshake.finalize(), "case {i} failed");
        }
    }
    #[test]
    fn cshake256() {
        let cases = [
            (
                vec![0, 1, 2, 3],
                64,
                "",
                "Email Signature",
                vec![
                    0xD0, 0x08, 0x82, 0x8E, 0x2B, 0x80, 0xAC, 0x9D, 0x22, 0x18, 0xFF, 0xEE, 0x1D,
                    0x07, 0x0C, 0x48, 0xB8, 0xE4, 0xC8, 0x7B, 0xFF, 0x32, 0xC9, 0x69, 0x9D, 0x5B,
                    0x68, 0x96, 0xEE, 0xE0, 0xED, 0xD1, 0x64, 0x02, 0x0E, 0x2B, 0xE0, 0x56, 0x08,
                    0x58, 0xD9, 0xC0, 0x0C, 0x03, 0x7E, 0x34, 0xA9, 0x69, 0x37, 0xC5, 0x61, 0xA7,
                    0x4C, 0x41, 0x2B, 0xB4, 0xC7, 0x46, 0x46, 0x95, 0x27, 0x28, 0x1C, 0x8C,
                ],
            ),
            (
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
                    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
                    0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
                    0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
                    0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81,
                    0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E,
                    0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B,
                    0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
                    0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
                    0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2,
                    0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
                ],
                64,
                "",
                "Email Signature",
                vec![
                    0x07, 0xDC, 0x27, 0xB1, 0x1E, 0x51, 0xFB, 0xAC, 0x75, 0xBC, 0x7B, 0x3C, 0x1D,
                    0x98, 0x3E, 0x8B, 0x4B, 0x85, 0xFB, 0x1D, 0xEF, 0xAF, 0x21, 0x89, 0x12, 0xAC,
                    0x86, 0x43, 0x02, 0x73, 0x09, 0x17, 0x27, 0xF4, 0x2B, 0x17, 0xED, 0x1D, 0xF6,
                    0x3E, 0x8E, 0xC1, 0x18, 0xF0, 0x4B, 0x23, 0x63, 0x3C, 0x1D, 0xFB, 0x15, 0x74,
                    0xC8, 0xFB, 0x55, 0xCB, 0x45, 0xDA, 0x8E, 0x25, 0xAF, 0xB0, 0x92, 0xBB,
                ],
            ),
        ];

        for (i, (x, olen, n, s, tgt)) in cases.into_iter().enumerate() {
            let mut cshake = CSHAKE256::new(olen, n.as_bytes(), s.as_bytes()).unwrap();
            cshake.write_all(x.as_slice()).unwrap();

            assert_eq!(tgt, cshake.finalize(), "case {i} failed");
        }
    }
}
