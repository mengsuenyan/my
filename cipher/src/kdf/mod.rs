use std::ops::{Deref, DerefMut};

use crate::CipherError;

pub trait KDF {
    // 密钥派生的最大长度
    fn max_key_size(&self) -> usize;

    fn kdf(&mut self, key_size: usize) -> Result<Vec<u8>, CipherError>;
}

impl<T: KDF> KDF for Box<T> {
    fn max_key_size(&self) -> usize {
        self.deref().max_key_size()
    }

    fn kdf(&mut self, key_size: usize) -> Result<Vec<u8>, CipherError> {
        self.deref_mut().kdf(key_size)
    }
}

mod scrypt;
pub use scrypt::Scrypt;
mod pbkdf;
pub use pbkdf::{PBKDF1, PBKDF2};
pub mod argon;
pub use argon::{Argon2, Params as ArgonParams, ParamsBuilder as ArgonParamsBuilder};
