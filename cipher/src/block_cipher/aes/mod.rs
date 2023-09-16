//! AES加密<br>
//! FIPS 197  <br>
//! [Blog](https://www.cnblogs.com/mengsuenyan/p/12697694.html)<br>
//! [FIPS 197-upd1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)<br>
//! this src modified from golang source code.<br>

/// AES is based on the mathematical behavior of binary polynomials<br>
/// (polynomials over GF(2)) modulo the irreducible polynomial x⁸ + x⁴ + x³ + x + 1.<br>
/// Addition of these binary polynomials corresponds to binary xor.<br>
/// Reducing mod poly corresponds to binary xor with poly every<br>
/// time a 0x100 bit appears.<br>
/// const poly = 1<<8 | 1<<4 | 1<<3 | 1<<1 | 1<<0 // x⁸ + x⁴ + x³ + x + 1<br>
#[derive(Clone)]
pub struct AES;

mod common;
mod const_;
mod generic;
pub use generic::{AES128, AES192, AES256};

#[cfg(test)]
mod tests;

use crate::{BlockCipherWrapper, BlockDecrypt, BlockEncrypt};

macro_rules! impl_block_cipher {
    ($NAME: ident) => {
        impl BlockEncrypt<16> for $NAME {
            fn encrypt_block(&self, plaintext: &[u8; 16]) -> [u8; 16] {
                self.encrypt_block_inner(plaintext)
            }
        }

        impl BlockDecrypt<16> for $NAME {
            fn decrypt_block(&self, ciphertext: &[u8; 16]) -> [u8; 16] {
                self.decrypt_block_inner(ciphertext)
            }
        }

        impl From<$NAME> for BlockCipherWrapper<$NAME, 16> {
            fn from(value: $NAME) -> Self {
                Self::new(value)
            }
        }
    };
}

impl_block_cipher!(AES128);
impl_block_cipher!(AES192);
impl_block_cipher!(AES256);
