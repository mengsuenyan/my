//! # BLAKE哈希函数
//!
//! ## BLAKE2哈希函数
//!
//! - 参考资料:
//!   - [BLAKE2](https://www.blake2.net/)
//!   - [BLAKE2: simpler, smaller, fast as MD5](https://www.blake2.net/blake2.pdf)
//!   - [RFC7693: The BLAKE2 Cryptographic Hash and Message Authentication Code](https://www.rfc-editor.org/rfc/pdfrfc/rfc7693.txt.pdf)
//! - 分类:
//!   - blake2b: 适用于64-bit平台;
//!     - blake2bp: blake2b并行版本;
//!   - blake2s: 适用于32-bit平台;
//!     - blake2sp: blake2s并行版本;
//!
//!

macro_rules! impl_blake2_common {
    ($NAME: ident, $WORD_TYPE: ty, $PARA: ty, $T_TYPE: ty) => {
        #[derive(Clone)]
        pub struct $NAME {
            buf: Vec<u8>,
            h: [$WORD_TYPE; 8],
            h_0: [$WORD_TYPE; 8],
            key: Vec<u8>,
            digest_len: u8,
            data_len: $T_TYPE,
            is_finalize: bool,
        }

        #[cfg(feature = "sec-zeroize")]
        impl zeroize::Zeroize for $NAME {
            fn zeroize(&mut self) {
                self.key.zeroize();
            }
        }

        impl $NAME {
            const SIGMA: [[usize; 16]; 10] = [
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
                [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
                [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
                [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
                [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
                [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
                [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
                [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
                [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
            ];

            pub fn new(desired_len: u8) -> Result<Self, crate::HashError> {
                Self::new_with_key(desired_len, Vec::with_capacity(0))
            }

            fn check_hash_bytes(s: u8) -> Result<(), crate::HashError> {
                if s == 0 || s > <$WORD_TYPE>::BITS as u8 {
                    Err(crate::HashError::Other(format!(
                        "{} digest size must to satisfy the `0 < s <= {}`",
                        stringify!($NAME),
                        <$WORD_TYPE>::BITS
                    )))
                } else {
                    Ok(())
                }
            }

            fn check_key_bytes(s: usize) -> Result<(), crate::HashError> {
                if s > <$WORD_TYPE>::BITS as usize {
                    Err(crate::HashError::Other(format!(
                        "{} key size must to satisfy the `0 <= s <= {}`",
                        stringify!($NAME),
                        <$WORD_TYPE>::BITS
                    )))
                } else {
                    Ok(())
                }
            }

            pub fn new_with_key(desired_len: u8, key: Vec<u8>) -> Result<Self, crate::HashError> {
                Self::check_hash_bytes(desired_len)?;
                Self::check_key_bytes(key.len())?;

                let (digest_len, key_len) = (desired_len as u8, key.len() as u8);
                let p = <$PARA>::new().digest_len(digest_len).key_len(key_len);
                let mut h = p.to_block();

                // h0 = IV ^ P
                h.iter_mut().zip(Self::IV).for_each(|(a, b)| *a ^= b);

                let (mut data_len, mut buf) = (0, Vec::with_capacity(Self::BLOCK_BYTES));
                if !key.is_empty() {
                    buf.extend_from_slice(key.as_slice());
                    buf.resize(Self::BLOCK_BYTES, 0);
                    data_len = Self::BLOCK_BYTES as $T_TYPE;
                }

                Ok(Self {
                    digest_len,
                    buf,
                    key,
                    h_0: h,
                    h,
                    data_len,
                    is_finalize: false,
                })
            }

            fn mix_g(
                v: &mut [$WORD_TYPE; 16],
                a: usize,
                b: usize,
                c: usize,
                d: usize,
                x: $WORD_TYPE,
                y: $WORD_TYPE,
            ) {
                v[a] = v[a].overflowing_add(v[b]).0.overflowing_add(x).0;
                v[d] = (v[d] ^ v[a]).rotate_right(Self::R1);
                v[c] = v[c].overflowing_add(v[d]).0;
                v[b] = (v[b] ^ v[c]).rotate_right(Self::R2);
                v[a] = v[a].overflowing_add(v[b]).0.overflowing_add(y).0;
                v[d] = (v[d] ^ v[a]).rotate_right(Self::R3);
                v[c] = v[c].overflowing_add(v[d]).0;
                v[b] = (v[b] ^ v[c]).rotate_right(Self::R4);
            }

            fn compress_f(h: &mut [$WORD_TYPE; 8], m: [$WORD_TYPE; 16], t: $T_TYPE, f: bool) {
                let mut v = [0; 16];
                v[..8].copy_from_slice(&*h);
                v[8..].copy_from_slice(&Self::IV);
                v[12] ^= t as $WORD_TYPE;
                v[13] ^= (t >> <$WORD_TYPE>::BITS) as $WORD_TYPE;

                if f {
                    v[14] ^= <$WORD_TYPE>::MAX;
                }

                for i in 0..Self::ROUND {
                    let s = Self::SIGMA[i % 10];
                    Self::mix_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
                    Self::mix_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
                    Self::mix_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                    Self::mix_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                    Self::mix_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
                    Self::mix_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                    Self::mix_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
                    Self::mix_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
                }

                for i in 0..8 {
                    h[i] ^= v[i] ^ v[i + 8];
                }
            }

            fn update(h: &mut [$WORD_TYPE; 8], m: [$WORD_TYPE; 16], data_len: $T_TYPE, f: bool) {
                Self::compress_f(h, m, data_len, f)
            }

            fn reset_inner(&mut self) {
                self.buf.clear();
                if !self.key.is_empty() {
                    self.buf.extend_from_slice(self.key.as_slice());
                    self.buf.resize(Self::BLOCK_BYTES, 0);
                    self.data_len = Self::BLOCK_BYTES as $T_TYPE;
                } else {
                    self.data_len = 0;
                }
                self.h = self.h_0;
                self.is_finalize = false;
            }
        }

        impl std::io::Write for $NAME {
            fn write(&mut self, mut data: &[u8]) -> std::io::Result<usize> {
                if self.is_finalize {
                    self.reset_inner();
                }

                let original_data_len = data.len();

                if !self.buf.is_empty() {
                    let l = data.len().min(Self::BLOCK_BYTES - self.buf.len());
                    self.buf.extend_from_slice(&data[..l]);
                    self.data_len += l as $T_TYPE;
                    data = &data[l..];

                    let mut m = [0; 16];
                    if self.buf.len() + data.len() > Self::BLOCK_BYTES {
                        self.buf
                            .chunks_exact(<$WORD_TYPE>::BITS as usize >> 3)
                            .zip(m.iter_mut())
                            .for_each(|(a, b)| {
                                *b = <$WORD_TYPE>::from_le_bytes(Block::to_arr_uncheck(a));
                            });
                        Self::update(&mut self.h, m, self.data_len, false);
                        self.buf.clear();
                    }
                }

                while data.len() > Self::BLOCK_BYTES {
                    let mut m = [0; 16];
                    let block = &data[..Self::BLOCK_BYTES];
                    block
                        .chunks_exact(<$WORD_TYPE>::BITS as usize >> 3)
                        .zip(m.iter_mut())
                        .for_each(|(a, b)| {
                            *b = <$WORD_TYPE>::from_le_bytes(Block::to_arr_uncheck(a));
                        });
                    self.data_len += Self::BLOCK_BYTES as $T_TYPE;
                    Self::update(&mut self.h, m, self.data_len, false);
                    data = &data[Self::BLOCK_BYTES..];
                }

                self.buf.extend_from_slice(data);
                self.data_len += data.len() as $T_TYPE;

                Ok(original_data_len)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl crate::XOF for $NAME {
            const BLOCK_BITS: usize = Self::BLOCK_BYTES << 3;
            const WORD_BITS: usize = Self::WORD_BYTES << 3;

            fn desired_len(&self) -> usize {
                self.digest_len as usize
            }

            fn finalize(&mut self) -> Vec<u8> {
                if !self.is_finalize {
                    let mut m = [0; 16];
                    self.buf.resize(Self::BLOCK_BYTES, 0);
                    self.buf
                        .chunks_exact(<$WORD_TYPE>::BITS as usize >> 3)
                        .zip(m.iter_mut())
                        .for_each(|(a, b)| {
                            *b = <$WORD_TYPE>::from_le_bytes(Block::to_arr_uncheck(a));
                        });
                    Self::update(&mut self.h, m, self.data_len, true);
                    self.is_finalize = true;
                }

                self.h
                    .iter()
                    .map(|x| x.to_le_bytes())
                    .flatten()
                    .take(self.digest_len as usize)
                    .collect()
            }

            fn reset(&mut self) {
                self.reset_inner();
            }
        }
    };
}

macro_rules! impl_blake2_spec {
    ($NAME: ident, $BITS: literal, $INNER: ty) => {
        #[derive(Clone)]
        pub struct $NAME {
            inner: $INNER,
        }

        impl $NAME {
            pub fn new() -> Self {
                Self {
                    inner: <$INNER>::new(($BITS >> 3) as u8).unwrap(),
                }
            }
        }

        #[cfg(feature = "sec-zeroize")]
        impl zeroize::Zeroize for $NAME {
            fn zeroize(&mut self) {
                self.inner.zeroize();
            }
        }

        impl Default for $NAME {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Write for $NAME {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.inner.write(buf)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }

        impl Digest for $NAME {
            const BLOCK_BITS: usize = <$INNER>::BLOCK_BITS;

            const WORD_BITS: usize = <$INNER>::WORD_BITS;
            const DIGEST_BITS: usize = $BITS;
            fn digest(msg: &[u8]) -> Output<Self> {
                let mut b = Self::new();
                b.write_all(msg).unwrap();
                b.finalize()
            }
            fn finalize(&mut self) -> Output<Self> {
                Output::from_vec(self.inner.finalize())
            }

            fn reset(&mut self) {
                self.inner.reset_inner();
            }
        }
    };
}

mod blake2_para;
pub use blake2_para::{Blake2bPara, Blake2sPara};
mod blake2b;
mod blake2s;

pub use blake2b::{BLAKE2b, BLAKE2b128, BLAKE2b224, BLAKE2b256, BLAKE2b384, BLAKE2b512};
pub use blake2s::{BLAKE2s, BLAKE2s128, BLAKE2s224, BLAKE2s256};
