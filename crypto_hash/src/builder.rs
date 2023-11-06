use crate::sm3::SM3;
use crate::DigestX;
use crate::{
    cshake::{CSHAKE128, CSHAKE256},
    sha2, sha3, HashError,
};
use std::convert::TryFrom;

macro_rules! impl_hasher_type {
    ($NAME: ident, $([$ITEM: tt $(=$VAL: literal)?]),+) => {
        #[repr(u32)]
        #[derive(Copy, Clone, Eq, PartialEq)]
        pub enum $NAME {
            $($ITEM $(=$VAL)?,)+
        }

        impl TryFrom<u32> for $NAME {
            type Error = HashError;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                match value {
                    $(x if x == Self::$ITEM as u32 => Ok(Self::$ITEM),)+
                    _ => {Err(HashError::Other(format!("{} is not valid HasherType value", value)))},
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::$NAME;
            #[test]
            fn check_hasher_type_repeat() {
                let mut x = [$($NAME::$ITEM as u64,)+].to_vec();
                x.sort();
                let len1 = x.len();
                x.dedup();
                assert_eq!(len1, x.len());
            }
        }
    };
}

impl_hasher_type!(
    HasherType,
    [SM3 = 0x10],
    [SHA1 = 0x20],
    [SHA2_224],
    [SHA2_256],
    [SHA2_384],
    [SHA2_512],
    [SHA2_512t],
    [SHA2_512T224],
    [SHA2_512T256],
    [SHA3_224 = 0x30],
    [SHA3_256],
    [SHA3_384],
    [SHA3_512],
    [SHAKE128],
    [SHAKE256],
    [CSHAKE128],
    [CSHAKE256]
);

#[derive(Clone)]
pub struct HasherBuilder {
    hasher: HasherType,
    desired_len: Option<usize>,
    // cshake使用的参数
    fuc_name: Option<Vec<u8>>,
    custom: Option<Vec<u8>>,
}

impl From<HasherType> for HasherBuilder {
    fn from(value: HasherType) -> Self {
        Self::new(value)
    }
}

impl HasherBuilder {
    pub fn new(hasher_type: HasherType) -> Self {
        Self {
            hasher: hasher_type,
            desired_len: None,
            fuc_name: None,
            custom: None,
        }
    }

    /// 对于XOF函数, 需要指定输出摘要的字节长度.
    /// 该值对Digest是不起作用的.
    pub fn desired_len(mut self, bytes: u32) -> Self {
        self.desired_len = Some(bytes as usize);
        self
    }

    pub fn cshake_para(mut self, fuc_name: &[u8], custom: &[u8]) -> Self {
        self.fuc_name = Some(fuc_name.to_vec());
        self.custom = Some(custom.to_vec());
        self
    }

    pub fn function_name(&self) -> Option<&[u8]> {
        self.fuc_name.as_deref()
    }

    pub fn custom_info(&self) -> Option<&[u8]> {
        self.custom.as_deref()
    }

    pub fn build(&self) -> Result<Box<dyn DigestX>, HashError> {
        let hasher: Box<dyn DigestX> = match self.hasher {
            HasherType::SM3 => {Box::new(SM3::new())},
            HasherType::SHA1 => {Box::new(sha2::SHA1::new())}
            HasherType::SHA2_224 => {Box::new(sha2::SHA224::new())}
            HasherType::SHA2_256 => {Box::new(sha2::SHA256::new())}
            HasherType::SHA2_384 => {Box::new(sha2::SHA384::new())}
            HasherType::SHA2_512 => {Box::new(sha2::SHA512::new())}
            HasherType::SHA2_512t => {
                Box::new(sha2::SHA512tInner::new(self.desired_len.ok_or(HashError::Other("The SHAKE128 is XOFs function that need to specify the desired digest byte lengths".to_string()))?)?)
            }
            HasherType::SHA2_512T224 => {Box::new(sha2::SHA512T224::new())}
            HasherType::SHA2_512T256 => {Box::new(sha2::SHA512T256::new())}
            HasherType::SHA3_224 => {Box::new(sha3::SHA224::new())}
            HasherType::SHA3_256 => {Box::new(sha3::SHA256::new())}
            HasherType::SHA3_384 => {Box::new(sha3::SHA384::new())}
            HasherType::SHA3_512 => {Box::new(sha3::SHA512::new())}
            HasherType::SHAKE128 => {
                Box::new(sha3::SHAKE128::new(self.desired_len.ok_or(HashError::Other("The SHAKE128 is XOFs function that need to specify the desired digest byte lengths".to_string()))?))
            }
            HasherType::SHAKE256 => {
                Box::new(sha3::SHAKE256::new(self.desired_len.ok_or(HashError::Other("The SHAKE256 is XOFs function that need to specify the desired digest byte lengths".to_string()))?))
            }
            HasherType::CSHAKE128 => {
                Box::new(CSHAKE128::new(
                    self.desired_len.ok_or(HashError::Other("The CSHAKE128 is XOFs function that need to specify the desired digest byte lengths".to_string()))?,
                    self.fuc_name.as_ref().ok_or(HashError::Other("The CSHAKE function need to specify the function name".to_string()))?,
                    self.custom.as_ref().ok_or(HashError::Other("The CSHAKE function need to specify the custom information".to_string()))?,
                )?)
            }
            HasherType::CSHAKE256 => {
                Box::new(CSHAKE256::new(
                    self.desired_len.ok_or(HashError::Other("The CSHAKE256 is XOFs function that need to specify the desired digest byte lengths".to_string()))?,
                    self.fuc_name.as_ref().ok_or(HashError::Other("The CSHAKE function need to specify the function name".to_string()))?,
                    self.custom.as_ref().ok_or(HashError::Other("The CSHAKE function need to specify the custom information".to_string()))?,
                )?)
            }
        };

        Ok(hasher)
    }

    /// 摘要类型标识号
    pub fn flag(self) -> Result<u64, HashError> {
        let x = (self.hasher as u64) << 32;
        let h = self.build()?;
        Ok(x | h.digest_bits_x() as u64)
    }
}
