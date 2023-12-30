use crate::{Digest, HashError};
use num_bigint::BigUint;
use std::{
    fmt::{Display, LowerHex, UpperHex},
    marker::PhantomData,
};
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

/// 消息哈希摘要输出。 按书写顺序存储, 即大端序.
#[derive(Clone, Debug)]
pub struct Output<T: ?Sized> {
    // Output是由哈希算法生成, 由实现算法保证`self.len() == Self::bytes()`
    pub(crate) data: Vec<u8>,
    pub(crate) digest: PhantomData<T>,
}

impl<T> Output<T> {
    pub fn iter(&self) -> std::slice::Iter<u8> {
        self.data.iter()
    }

    pub(crate) const fn from_vec(digest: Vec<u8>) -> Self {
        Self {
            data: digest,
            digest: PhantomData,
        }
    }

    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_vec(self) -> Vec<u8> {
        self.data
    }

    /// 字节长度
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// `Output`字节长度超过`N`会截断输出低`N`字节, `Output`字节长度小于`N`高字节会补0.
    /// 大端序
    pub fn to_array<const N: usize>(&self) -> [u8; N] {
        let mut arr = [0u8; N];

        match self.len().cmp(&N) {
            std::cmp::Ordering::Less => arr[(N - self.len())..].copy_from_slice(self.as_ref()),
            std::cmp::Ordering::Equal => arr.copy_from_slice(self.as_ref()),
            std::cmp::Ordering::Greater => arr.copy_from_slice(&self.as_ref()[(self.len() - N)..]),
        }

        arr
    }

    /// 获取第`index`字节的数据, 从`0`开始索引.
    pub fn byte(&self, index: usize) -> Option<u8> {
        self.as_ref()
            .get(self.len().saturating_sub(index + 1))
            .copied()
    }

    /// 获取第`index`字节的位数据, 从`0`开始索引.
    pub fn bit(&self, index: usize) -> Option<bool> {
        self.byte((index + 7) / 8)
            .map(|d| (d & (1u8 << (index % 8))) > 0)
    }
}

impl<T: Digest> Output<T> {
    /// 字节长度
    pub const fn bytes() -> usize {
        (<T>::DIGEST_BITS + 7) >> 3
    }

    /// 位长度
    pub const fn bits() -> usize {
        <T>::DIGEST_BITS
    }
}

impl<T: Digest, const N: usize> TryFrom<[u8; N]> for Output<T> {
    type Error = HashError;

    /// `N != Self::bytes()`会返回`None`
    fn try_from(value: [u8; N]) -> Result<Self, Self::Error> {
        if N == Self::bytes() {
            Ok(Self::from_vec(value.to_vec()))
        } else {
            Err(HashError::MismatchingByteLen {
                target: Self::bytes(),
                real: N,
            })
        }
    }
}

#[cfg(feature = "sec-zeroize")]
impl<T: Digest> Zeroize for Output<T> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<T> AsRef<[u8]> for Output<T> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// `N`必须和`Output.len()`匹配, 否则会返回`HashError`.
impl<T: Digest, const N: usize> TryFrom<Output<T>> for [u8; N] {
    type Error = HashError;

    fn try_from(value: Output<T>) -> Result<Self, Self::Error> {
        if N != Output::<T>::bytes() {
            Err(HashError::MismatchingByteLen {
                target: N,
                real: Output::<T>::bytes(),
            })
        } else {
            let mut arr = [0u8; N];
            arr.copy_from_slice(value.as_ref());

            Ok(arr)
        }
    }
}

impl<T> From<Output<T>> for Vec<u8> {
    fn from(value: Output<T>) -> Self {
        value.data
    }
}

impl<T> Display for Output<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = BigUint::from_bytes_be(self.as_ref());
        f.write_fmt(format_args!("{}", n))
    }
}

impl<T> LowerHex for Output<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        for &b in self.as_ref() {
            f.write_fmt(format_args!("{:02x}", b))?;
        }

        Ok(())
    }
}

impl<T> UpperHex for Output<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.write_str("0X")?;
        }
        for &b in self.as_ref() {
            f.write_fmt(format_args!("{:02X}", b))?;
        }

        Ok(())
    }
}
