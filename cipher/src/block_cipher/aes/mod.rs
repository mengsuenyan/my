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

use crate::BlockCipher;
use crate::CipherError;

macro_rules! impl_block_ciper {
    ($NAME: ident) => {
        impl BlockCipher for $NAME {
            type Err = CipherError;

            const BLOCK_SIZE: usize = 16;

            fn encrypt(&self, plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), Self::Err> {
                if plaintext.len() == Self::BLOCK_SIZE {
                    let data = unsafe { &*(plaintext.as_ptr() as *const [u8; Self::BLOCK_SIZE]) };

                    ciphertext.extend(self.crypt_block(data));
                    Ok(())
                } else {
                    Err(CipherError::InvalidBlockSize {
                        target: Self::BLOCK_SIZE,
                        real: plaintext.len(),
                    })
                }
            }

            fn decrypt(&self, ciphertext: &[u8], plaintext: &mut Vec<u8>) -> Result<(), Self::Err> {
                if ciphertext.len() == Self::BLOCK_SIZE {
                    let data = unsafe { &*(ciphertext.as_ptr() as *const [u8; Self::BLOCK_SIZE]) };
                    plaintext.extend(self.decrypt_block(data));

                    Ok(())
                } else {
                    Err(CipherError::InvalidBlockSize {
                        target: Self::BLOCK_SIZE,
                        real: plaintext.len(),
                    })
                }
            }
        }
    };
}

impl_block_ciper!(AES128);
impl_block_ciper!(AES192);
impl_block_ciper!(AES256);
