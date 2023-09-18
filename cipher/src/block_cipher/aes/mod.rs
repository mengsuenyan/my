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
pub enum AES {
    AES128(AES128),
    AES192(AES192),
    AES256(AES256),
}

mod common;
mod const_;
mod generic;
pub use generic::{AES128, AES192, AES256};

#[cfg(test)]
mod tests;

use crate::{BlockDecrypt, BlockEncrypt, CipherError, Decrypt, Encrypt};
use utils::Block;

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

        impl Encrypt for $NAME {
            fn encrypt(
                &self,
                plaintext: &[u8],
                ciphertext: &mut Vec<u8>,
            ) -> Result<(), CipherError> {
                match Block::as_arr_ref(plaintext) {
                    Some(block) => {
                        ciphertext.extend(self.encrypt_block(block));
                        Ok(())
                    }
                    None => Err(CipherError::InvalidBlockSize {
                        target: 16,
                        real: plaintext.len(),
                    }),
                }
            }
        }

        impl Decrypt for $NAME {
            fn decrypt(
                &self,
                ciphertext: &[u8],
                plaintext: &mut Vec<u8>,
            ) -> Result<(), CipherError> {
                match Block::as_arr_ref(ciphertext) {
                    Some(block) => {
                        plaintext.extend(self.decrypt_block(block));
                        Ok(())
                    }
                    None => Err(CipherError::InvalidBlockSize {
                        target: 16,
                        real: ciphertext.len(),
                    }),
                }
            }
        }
    };
}

impl_block_cipher!(AES128);
impl_block_cipher!(AES192);
impl_block_cipher!(AES256);
impl_block_cipher!(AES);
