/// 实现标准: [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)<br>
///
///
use std::ops::{BitAnd, BitXor, Not};

#[inline]
fn f_ch<T>(x: T, y: T, z: T) -> T
where
    T: Not<Output = T> + BitXor<Output = T> + BitAnd<Output = T> + Copy,
{
    (x & y) ^ ((!x) & z)
}

#[inline]
fn f_parity(x: u32, y: u32, z: u32) -> u32 {
    (x ^ y) ^ z
}

#[inline]
fn f_maj<T>(x: T, y: T, z: T) -> T
where
    T: Not<Output = T> + BitXor<Output = T> + BitAnd<Output = T> + Copy,
{
    (x & y) ^ (x & z) ^ (y & z)
}

/// 数据按划分为块, 每个块再划分为若干单词进行哈希处理. 数据的总长度需填充到DATA_PADDING_BYTES*8的
/// 整数倍(实规范上是DATA_PADDING_BITS位长度的整数倍, 现实使用中的数据都是字节的整数倍, 所以这里简化处理了)
/// 最后再将实际数据的位长度填充到LEN_PADDING_TYPE::BITS长度的空间中, 以使得填充后的数据长度是BLOCK_BITS的整数倍.<br>
/// <br>
/// $NAME: 结构体的名字<br>
/// $WORD_TYPE: 存储一个单词使用的类型<br>
/// $BLOCK_BITS: 块位长度<br>
/// $WORD_BITS: 单词位长度<br>
/// $DIGEST_BITS: 摘要位长度<br>
/// $DATA_PADDING_BYTES: 数据需填充到该字节的整数倍<br>
/// $LEN_PADDING_TYPE: 数据的位长度需要填充进哈希处理的数据中<br>
/// $INIT_CONST: 摘要初始化常量值, 参考FIPS 180-4<br>
/// $K: 哈希过程中的常量值, 参考FIPS 180-4<br>
/// $K_SIZE: $K常量个数
macro_rules! sha_common {
    (
        $NAME: ident,
        $WORD_TYPE: ty,
        $BLOCK_BITS: literal,
        $WORD_BITS: literal,
        $DIGEST_BITS: literal,
        $DATA_PADDING_BYTES: literal,
        $LEN_PADDING_TYPE: ty,
        $INIT_CONST: expr,
        $K_CONST: expr,
        $K_SIZE: literal
    ) => {
        use crate::{Digest, Output};
        use std::io::Write;
        #[cfg(feature = "sec-zeroize")]
        use zeroize::Zeroize;

        /// 实现标准: [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
        #[derive(Clone)]
        pub struct $NAME {
            digest: [$WORD_TYPE; Self::DIGEST_WSIZE],
            buf: [u8; Self::BLOCK_SIZE],
            // 记录buf下一个可写入位置的索引
            idx: usize,
            // 记录已写入数据的总长度
            len: usize,
            is_finalize: bool,
        }

        impl $NAME {
            pub(in crate::sha2) const BLOCK_SIZE: usize = $BLOCK_BITS / 8;
            pub(in crate::sha2) const WORD_NUMS: usize = $BLOCK_BITS / $WORD_BITS;
            pub(in crate::sha2) const DIGEST_WSIZE: usize = $DIGEST_BITS / $WORD_BITS;
            pub(in crate::sha2) const INIT: [$WORD_TYPE; $NAME::DIGEST_WSIZE] = $INIT_CONST;
            pub(in crate::sha2) const K: [$WORD_TYPE; $K_SIZE] = $K_CONST;

            pub const fn new() -> Self {
                Self::new_with_init($NAME::INIT)
            }

            pub(in crate::sha2) const fn new_with_init(
                init: [$WORD_TYPE; $NAME::DIGEST_WSIZE],
            ) -> Self {
                Self {
                    digest: init,
                    buf: [0; $NAME::BLOCK_SIZE],
                    idx: 0,
                    len: 0,
                    is_finalize: false,
                }
            }
        }

        #[cfg(feature = "sec-zeroize")]
        impl Zeroize for $NAME {
            fn zeroize(&mut self) {
                self.digest.zeroize();
                self.buf.zeroize();
            }
        }

        impl Default for $NAME {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Write for $NAME {
            fn write(&mut self, mut data: &[u8]) -> std::io::Result<usize> {
                if self.is_finalize {
                    self.reset();
                }
                let data_len = data.len();

                if self.idx > 0 {
                    let ava_len = data.len().min(Self::BLOCK_SIZE - self.idx);
                    self.buf[self.idx..(self.idx + ava_len)].copy_from_slice(&data[0..ava_len]);
                    self.idx += ava_len;

                    if self.idx == Self::BLOCK_SIZE {
                        Self::update(&mut self.digest, self.buf.as_ref());
                        self.idx = 0;
                    }

                    data = &data[ava_len..];
                }

                if data.len() > Self::BLOCK_SIZE {
                    let n = data.len() & (!(Self::BLOCK_SIZE - 1));
                    Self::update(&mut self.digest, &data[0..n]);
                    data = &data[n..];
                }

                if !data.is_empty() {
                    self.buf[0..data.len()].copy_from_slice(data);
                    self.idx += data.len();
                }

                self.len += data_len;
                Ok(data_len)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl Digest for $NAME {
            const BLOCK_BITS: usize = $BLOCK_BITS;
            const WORD_BITS: usize = $WORD_BITS;
            const DIGEST_BITS: usize = $DIGEST_BITS;

            fn digest(msg: &[u8]) -> Output<Self> {
                let mut sha = Self::new();
                sha.write_all(msg).unwrap();
                sha.finalize()
            }

            fn finalize(&mut self) -> Output<Self> {
                if self.is_finalize {
                    return crate::Output::from_vec(
                        self.digest.iter().flat_map(|x| x.to_be_bytes()).collect(),
                    );
                }
                let mut padding = [0u8; Self::BLOCK_SIZE];
                padding[0] = 0x80;
                // 数据长度填充为$DATA_PADDING_BYTES * 8位的整数倍
                let real_len = self.len;
                let len = real_len % Self::BLOCK_SIZE;
                if len < $DATA_PADDING_BYTES {
                    self.write_all(&padding[0..($DATA_PADDING_BYTES - len)])
                        .unwrap();
                } else {
                    self.write_all(&padding[0..(Self::BLOCK_SIZE + $DATA_PADDING_BYTES - len)])
                        .unwrap();
                }

                // 注意是实际数据的长度
                self.write_all(
                    ((real_len as $LEN_PADDING_TYPE) << 3)
                        .to_be_bytes()
                        .as_ref(),
                )
                .unwrap();

                self.is_finalize = true;
                crate::Output::from_vec(self.digest.iter().flat_map(|x| x.to_be_bytes()).collect())
            }

            fn reset(&mut self) {
                *self = Self::new();
            }
        }
    };
    (
        $NAME: ident,
        $PARENT: ty,
        $BLOCK_BITS: literal,
        $WORD_BITS: literal,
        $DIGEST_BITS: literal,
        $INIT_CONST: expr
    ) => {
        #[derive(Clone)]
        pub struct $NAME {
            sha: $PARENT,
        }

        #[cfg(feature = "sec-zeroize")]
        impl Zeroize for $NAME {
            fn zeroize(&mut self) {
                self.sha.zeroize();
            }
        }

        impl Default for $NAME {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Write for $NAME {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.sha.write(data)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.sha.flush()
            }
        }

        impl Digest for $NAME {
            const BLOCK_BITS: usize = $BLOCK_BITS;
            const WORD_BITS: usize = $WORD_BITS;
            const DIGEST_BITS: usize = $DIGEST_BITS;

            fn digest(msg: &[u8]) -> Output<Self> {
                let mut sha = Self::new();
                sha.write_all(msg).unwrap();
                sha.finalize()
            }

            fn finalize(&mut self) -> Output<Self> {
                let mut v = self.sha.finalize().to_vec();
                v.truncate($DIGEST_BITS / 8);
                Output::from_vec(v)
            }

            fn reset(&mut self) {
                *self = Self::new();
            }
        }

        impl $NAME {
            pub const fn new() -> Self {
                Self {
                    sha: <$PARENT>::new_with_init($INIT_CONST),
                }
            }
        }
    };
}

mod amd64;
mod generic;

mod sha1;
pub use sha1::SHA1;
mod sha256;
pub use sha256::{SHA224, SHA256};
mod sha512;
pub use sha512::{SHA512t, SHA512tInner, SHA384, SHA512, SHA512T224, SHA512T256};
