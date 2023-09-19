use crate::CipherError;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::ops::Range;
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

/// CTR模式使用的计数器, 需要保证每个分组生成的计数值保证独一无二的 <br>
pub trait Counter {
    /// 获取新计数值
    fn count(&mut self) -> Option<Vec<u8>>;

    /// 计数范围位数
    fn range_bits(&self) -> usize;

    /// 初始化向量字节数
    fn iv_bytes(&self) -> usize;
}

/// 默认的计数器是递增计数器, 每次加解密调用者保证给定的初始向量是独一无的, 还需确保
/// 给定的递增范围的位长度是大于分组的位长度. 如此, 能保证每次加解密每个分组使用的计
/// 数值都是独一无二的
#[derive(Clone)]
pub struct DefaultCounter {
    // iv = mark | (ivr << range.start)
    mark: BigUint,
    // 指定递增的范围
    range: Range<usize>,
    // 递增初始值
    ivr: BigUint,
    // 递增值
    cnt: Option<BigUint>,
    // 初始化向量字节长度
    len: usize,
}

impl DefaultCounter {
    /// `iv`指定初始化向量, 位长度为`iv.len() * 8`; <br>
    /// `range`指定计数的范围;
    pub fn new(mut iv: Vec<u8>, range: Range<usize>) -> Result<Self, CipherError> {
        let bits = iv.len() << 3;
        if range.is_empty() {
            return Err(CipherError::Other(format!(
                "counter range {:?} is empty",
                range
            )));
        } else if range.end > bits {
            return Err(CipherError::Other(format!(
                "counter range {:?} out of the iv bit range `[0,{bits})`",
                range
            )));
        }

        let mark = (BigUint::one() << (range.end - range.start)) - 1u8;
        let ivb = BigUint::from_bytes_be(iv.as_slice());
        let ivr = (&ivb >> range.start) & mark;
        let start = &ivb & ((BigUint::one() << range.start) - 1u8);
        let mark = ((ivb >> range.end) << range.end) | start;
        let cnt = Some(ivr.clone());

        #[cfg(feature = "sec-zeroize")]
        iv.zeroize();

        Ok(Self {
            mark,
            range,
            ivr,
            cnt,
            len: bits >> 3,
        })
    }
}

#[cfg(feature = "sec-zeroize")]
impl Zeroize for DefaultCounter {
    fn zeroize(&mut self) {
        use num_bigint::RandomBits;
        use xrand::distributions::Distribution;
        use xrand::rngs::OsRng;
        let (mut rng, rb) = (OsRng, RandomBits::new((self.len << 3) as u64));
        let r: BigUint = rb.sample(&mut rng);
        self.mark |= &r;
        self.ivr |= r;
        self.range = Range { start: 0, end: 0 };
    }
}

impl Counter for DefaultCounter {
    fn count(&mut self) -> Option<Vec<u8>> {
        let v = self
            .cnt
            .as_ref()
            .map(|x| (&self.mark | (x << self.range.start)).to_bytes_be());

        let bits = self.range_bits() as u64;
        if let Some(cnt) = self.cnt.as_mut() {
            *cnt += 1u8;

            if cnt.bits() > bits {
                *cnt = BigUint::zero();
            }
        }

        if self.cnt.as_ref() == Some(&self.ivr) {
            self.cnt = None;
        }

        v
    }

    fn range_bits(&self) -> usize {
        self.range.end - self.range.start
    }

    fn iv_bytes(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher_mode::{Counter, DefaultCounter};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::ops::Range;

    #[test]
    fn default_counter() {
        let cases = [
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdff02",
        ]
        .into_iter()
        .map(|x| BigUint::from_str_radix(x, 16).unwrap().to_bytes_be())
        .collect::<Vec<_>>();

        let mut cnt = DefaultCounter::new(cases[0].clone(), Range { start: 0, end: 128 }).unwrap();

        for (i, case) in cases.into_iter().enumerate() {
            let c = cnt.count();
            assert_eq!(c, Some(case), "case {i} failed");
        }
    }
}
