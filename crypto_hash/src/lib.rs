use std::io::Write;
use std::ops::{Deref, DerefMut};

mod output;
pub use output::Output;

mod error;
pub use error::HashError;

macro_rules! impl_digestx_for_xof {
    ($NAME1: ty, $($NAME2: ty),+) => {
        impl_digestx_for_xof!($NAME1);
        impl_digestx_for_xof!($($NAME2),+);
    };
    ($NAME: ty) => {
        impl DigestX for $NAME {
            fn block_bits_x(&self) -> usize {
                <Self as XOF>::BLOCK_BITS
            }

            fn word_bits_x(&self) -> usize {
                <Self as XOF>::WORD_BITS
            }

            fn digest_bits_x(&self) -> usize {
                self.desired_len() << 3
            }

            fn finish_x(&mut self) -> Vec<u8> {
                self.finalize()
            }

            fn reset_x(&mut self) {
                self.reset()
            }
        }
    };
}

pub mod cshake;
pub mod keccak;
pub mod sha2;
pub mod sha3;
pub mod sm3;

pub mod blake;
pub mod builder;

pub use builder::{HasherBuilder, HasherType};

/// 哈希算法实现该trait, 计算消息的摘要. 可直接调用`Digest::digest(msg)`生成消息的摘要, 或者通过`Write` trait将数据更新
/// 到`self`中后使用`self.finalize()`生成消息摘要.
///
/// 可用于如下安全应用中:
/// - 数据一致性验证;
/// - 参与数字签名的生成和验证;
/// - 密钥派生;
/// - 伪随机数生成;
pub trait Digest: Write {
    /// 哈希算法每次按块处理消息的块的位长度
    const BLOCK_BITS: usize;
    /// 哈希算法将每个块按该位长度划分为若干个单词
    const WORD_BITS: usize;
    /// 哈希算法生成的摘要的位长度
    const DIGEST_BITS: usize;

    /// 生成消息摘要
    fn digest(msg: &[u8]) -> Output<Self>;

    /// 生成消息摘要
    fn finalize(&mut self) -> Output<Self>;

    /// 重置哈希算法到初始化状态
    fn reset(&mut self);
}

pub trait DigestX: Write {
    fn block_bits_x(&self) -> usize;
    fn word_bits_x(&self) -> usize;
    fn digest_bits_x(&self) -> usize;
    fn finish_x(&mut self) -> Vec<u8>;
    fn digest(&mut self, msg: &[u8]) -> Vec<u8> {
        self.reset_x();
        self.write_all(msg).unwrap();
        let x = self.finish_x();
        self.reset_x();
        x
    }
    fn reset_x(&mut self);
}

impl<T> DigestX for T
where
    T: Digest,
{
    fn block_bits_x(&self) -> usize {
        <T as Digest>::BLOCK_BITS
    }

    fn word_bits_x(&self) -> usize {
        <T as Digest>::BLOCK_BITS
    }
    fn digest_bits_x(&self) -> usize {
        <T as Digest>::DIGEST_BITS
    }
    fn finish_x(&mut self) -> Vec<u8> {
        self.finalize().to_vec()
    }
    fn reset_x(&mut self) {
        self.reset()
    }
}

impl DigestX for Box<dyn DigestX> {
    fn block_bits_x(&self) -> usize {
        self.deref().block_bits_x()
    }
    fn word_bits_x(&self) -> usize {
        self.deref().word_bits_x()
    }

    fn digest_bits_x(&self) -> usize {
        self.deref().digest_bits_x()
    }

    fn finish_x(&mut self) -> Vec<u8> {
        self.deref_mut().finish_x()
    }

    fn reset_x(&mut self) {
        self.deref_mut().reset_x()
    }
}

/// Extendable-output function <br>
pub trait XOF: Write {
    const BLOCK_BITS: usize;
    const WORD_BITS: usize;
    // 期望输出摘要的字节大小
    fn desired_len(&self) -> usize;

    fn finalize(&mut self) -> Vec<u8>;

    fn reset(&mut self);
}

pub trait XOFx: Write {
    fn block_bits_x(&self) -> usize;
    fn word_bits_x(&self) -> usize;

    fn desired_len_x(&self) -> usize;
    fn finalize_x(&mut self) -> Vec<u8>;
    fn reset_x(&mut self);
}
impl<T> XOFx for T
where
    T: XOF,
{
    fn block_bits_x(&self) -> usize {
        <T as XOF>::BLOCK_BITS
    }

    fn word_bits_x(&self) -> usize {
        <T as XOF>::WORD_BITS
    }

    fn desired_len_x(&self) -> usize {
        self.desired_len()
    }

    fn finalize_x(&mut self) -> Vec<u8> {
        self.finalize()
    }

    fn reset_x(&mut self) {
        self.reset()
    }
}
