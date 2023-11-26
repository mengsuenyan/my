use crate::CipherError;
use std::convert::TryFrom;

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
    [AES128],
    [AES192],
    [AES256]
);

impl_cipher_type!(PaddingType, u8, [EmptyPadding], [DefaultPadding]);

impl_cipher_type!(CounterType, u8, [DefaultCounter = 0x1]);

impl_cipher_type!(
    CipherType,
    u16,
    [CCM = 0x1],
    [GCM],
    [ECB],
    [CBC],
    [CBCCS1],
    [CBCCS2],
    [CBCCS3],
    [CFB],
    [OFB],
    [CTR],
    [ZUC]
);

#[derive(Clone)]
pub struct CipherBuilder {
    block_cipher_type: BlockCipherType,
    cipher_type: Option<CipherType>,
    padding_type: Option<PaddingType>,
    counter_type: Option<CounterType>,
}

impl CipherBuilder {
    pub fn new(block_cipher_type: BlockCipherType) -> Self {
        Self {
            block_cipher_type,
            cipher_type: None,
            padding_type: None,
            counter_type: None,
        }
    }

    pub fn key_size(&self) -> usize {
        match self.block_cipher_type {
            BlockCipherType::SM4 => {128 / 8}
            BlockCipherType::AES128 => {128 / 8}
            BlockCipherType::AES192 => {192 / 8}
            BlockCipherType::AES256 => {256 / 8}
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
}
