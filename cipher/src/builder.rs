use crate::block_cipher::{BlockCipherX, AES128, AES192, AES256, SM4};
use crate::CipherError;
use std::convert::TryFrom;
use zeroize::Zeroize;

macro_rules! impl_cipher_type {
    ($NAME: ident, $REPR: ty, $([$ITEM: tt $(=$VAL: literal)?]),+) => {
        #[repr($REPR)]
        #[derive(Copy, Clone, Eq, PartialEq)]
        pub enum $NAME {
            $($ITEM $(=$VAL)?,)+
        }

        impl TryFrom<$REPR> for $NAME {
            type Error = CipherError;

            fn try_from(value: $REPR) -> Result<Self, Self::Error> {
                match value {
                    $(x if x == Self::$ITEM as $REPR => Ok(Self::$ITEM),)+
                    _ => { Err(CipherError::Other(format!("{} is no valid CipherType value", value))) },
                }
            }
        }

        impl $NAME {
            pub fn all_type_names() -> Vec<String> {
                vec![$(stringify!($ITEM).to_lowercase(),)+]
            }

            pub fn name(self) -> String {
                match self {
                    $(Self::$ITEM => stringify!($ITEM).to_lowercase(),)+
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use super::$NAME;

            #[test]
            fn check_cipher_type_repeat() {
                let mut x = [$($NAME::$ITEM as u64),+].to_vec();
                x.sort();
                let len1 = x.len();
                x.dedup();
                assert_eq!(len1, x.len());
            }
        }
    };
}

impl_cipher_type!(
    BlockCipherType,
    u16,
    [SM4 = 0x1],
    [AES128 = 0x2],
    [AES192 = 0x3],
    [AES256 = 0x4]
);

impl_cipher_type!(PaddingType, u8, [Empty], [Default]);

impl_cipher_type!(CounterType, u8, [Default = 0x1]);

impl_cipher_type!(
    CipherType,
    u16,
    [CCM = 0x1],
    [GCM = 0x2],
    [ECB = 0x3],
    [CBC = 0x4],
    [CBCCS1 = 0x5],
    [CBCCS2 = 0x6],
    [CBCCS3 = 0x7],
    [CFB = 0x8],
    [OFB = 0x9],
    [CTR = 0xa],
    [ZUC = 0xb]
);

#[derive(Clone)]
pub struct CipherBuilder {
    block_cipher_type: BlockCipherType,
    cipher_type: Option<CipherType>,
    padding_type: Option<PaddingType>,
    counter_type: Option<CounterType>,
    key: Vec<u8>,
}

impl CipherBuilder {
    pub fn new(block_cipher_type: BlockCipherType) -> Self {
        Self {
            block_cipher_type,
            cipher_type: None,
            padding_type: None,
            counter_type: None,
            key: vec![],
        }
    }

    pub fn cipher_type(mut self, cipher_type: CipherType) -> Self {
        self.cipher_type = Some(cipher_type);
        self
    }

    pub fn padding_type(mut self, padding_type: PaddingType) -> Self {
        self.padding_type = Some(padding_type);
        self
    }

    pub fn counter_type(mut self, counter_type: CounterType) -> Self {
        self.counter_type = Some(counter_type);
        self
    }

    pub fn set_key(mut self, key: Vec<u8>) -> Self {
        self.key.zeroize();
        self.key = key;
        self
    }

    pub fn build_block_cipher(&self) -> Result<Box<dyn BlockCipherX>, CipherError> {
        let block: Box<dyn BlockCipherX> =
            match self.block_cipher_type {
                BlockCipherType::SM4 => {
                    let key = self.key.as_slice().try_into().map_err(|_| {
                        CipherError::InvalidKeySize {
                            real: self.key.len(),
                            target: Some(SM4::KEY_SIZE),
                        }
                    })?;
                    Box::new(SM4::new(key))
                }
                BlockCipherType::AES128 => {
                    let key = self.key.as_slice().try_into().map_err(|_| {
                        CipherError::InvalidKeySize {
                            real: self.key.len(),
                            target: Some(AES128::KEY_SIZE),
                        }
                    })?;
                    Box::new(AES128::new(key))
                }
                BlockCipherType::AES192 => {
                    let key = self.key.as_slice().try_into().map_err(|_| {
                        CipherError::InvalidKeySize {
                            real: self.key.len(),
                            target: Some(AES192::KEY_SIZE),
                        }
                    })?;
                    Box::new(AES128::new(key))
                }
                BlockCipherType::AES256 => {
                    let key = self.key.as_slice().try_into().map_err(|_| {
                        CipherError::InvalidKeySize {
                            real: self.key.len(),
                            target: Some(AES256::KEY_SIZE),
                        }
                    })?;
                    Box::new(AES128::new(key))
                }
            };

        Ok(block)
    }
}
