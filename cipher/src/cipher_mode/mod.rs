//! # Recommendation for Block Cipher Mode of Operation: Method and Techniques
//!
//! [Block Cipher Techniques](https://csrc.nist.gov/Projects/block-cipher-techniques/BCM/current-modes)<br>
//! [NIST 800-38A, Recommendation for Block Cipher Modes of operation Methods and Techniques](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)<br>
//! [NIST 800-38A-add, Three Variants of Ciphertext Stealing for CBC mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a-add.pdf)
//!

macro_rules! impl_set_working_flag {
    ($NAME: ident) => {
        impl<P, E, const N: usize> $NAME<P, E, N> {
            fn set_working_flag(&mut self, is_encrypt: bool) -> Result<(), CipherError> {
                match self.is_encrypt {
                    None => {
                        self.data.clear();
                        self.out_buf.clear();
                        self.is_encrypt = Some(is_encrypt);
                        Ok(())
                    }
                    Some(b) => {
                        if b != is_encrypt {
                            Err(CipherError::BeWorking(b))
                        } else {
                            Ok(())
                        }
                    }
                }
            }
        }
    };
}

macro_rules! def_type_block_cipher {
    ($MODE: ident, [$NAME:ident, $TY: ty]) => {
        pub type $NAME<T> = $MODE<T, $TY, {<$TY>::BLOCK_SIZE}>;
    };
    ($MODE: ident, <$NAME:ident, $TY: ty>) => {
        pub type $NAME = $MODE<$TY, {<$TY>::BLOCK_SIZE}>;
    };
    ($MODE: ident, [$NAME1: ident, $TY1: ty], $([$NAME2: ident, $TY2: ty]),+) => {
        def_type_block_cipher!($MODE, [$NAME1, $TY1]);
        def_type_block_cipher!($MODE, $([$NAME2, $TY2]),+);
    };
    ($MODE: ident, <$NAME1: ident, $TY1: ty>, $(<$NAME2: ident, $TY2: ty>),+) => {
        def_type_block_cipher!($MODE, <$NAME1, $TY1>);
        def_type_block_cipher!($MODE, $(<$NAME2, $TY2>),+);
    };
}

mod padding;
pub use padding::{BlockPadding, DefaultPadding, EmptyPadding};

mod ecb;
pub use ecb::{AES128Ecb, AES192Ecb, AES256Ecb, AESEcb, ECB};

mod cbc;
pub use cbc::{AES128Cbc, AES192Cbc, AES256Cbc, AESCbc, CBC};

mod cfb;
pub use cfb::{AES128Cfb, AES192Cfb, AES256Cfb, AESCfb, CFB};

mod ofb;
pub use ofb::{AES128Ofb, AES192Ofb, AES256Ofb, AESOfb, OFB};

mod counter;
pub use counter::{Counter, DefaultCounter};

mod ctr;
pub use ctr::{AES128Ctr, AES192Ctr, AES256Ctr, AESCtr, CTR};
