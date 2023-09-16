use crate::{CipherError, Decrypt, Encrypt};
use std::ops::Deref;

pub trait BlockEncrypt<const BLOCK_SIZE: usize> {
    fn encrypt_block(&self, plaintext: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE];
}

pub trait BlockDecrypt<const BLOCK_SIZE: usize> {
    fn decrypt_block(&self, ciphertext: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE];
}

pub trait BlockCipher<const N: usize>: BlockEncrypt<N> + BlockDecrypt<N> {
    const BLOCK_SIZE: usize = N;
}

impl<T, const N: usize> BlockCipher<N> for T where T: BlockDecrypt<N> + BlockEncrypt<N> {}

pub struct BlockCipherWrapper<T, const BLOCK_SIZE: usize> {
    wrapper: T,
}

impl<T, const N: usize> BlockCipherWrapper<T, N> {
    pub fn new(wrapper: T) -> Self {
        Self { wrapper }
    }
}

impl<T, const N: usize> Deref for BlockCipherWrapper<T, N> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.wrapper
    }
}

impl<T, const BLOCK_SIZE: usize> Encrypt for BlockCipherWrapper<T, BLOCK_SIZE>
where
    T: BlockEncrypt<BLOCK_SIZE>,
{
    fn encrypt(&self, plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), CipherError> {
        if plaintext.len() == BLOCK_SIZE {
            // 因为拥有plaintext的所有权, 所以是安全的
            let data = unsafe {
                let ptr = plaintext.as_ptr() as *const [u8; BLOCK_SIZE];
                &*ptr
            };

            ciphertext.extend(self.encrypt_block(data));

            Ok(())
        } else {
            Err(CipherError::InvalidBlockSize {
                target: BLOCK_SIZE,
                real: plaintext.len(),
            })
        }
    }
}

impl<T, const BLOCK_SIZE: usize> Decrypt for BlockCipherWrapper<T, BLOCK_SIZE>
where
    T: BlockDecrypt<BLOCK_SIZE>,
{
    fn decrypt(&self, ciphertext: &[u8], plaintext: &mut Vec<u8>) -> Result<(), CipherError> {
        if ciphertext.len() == BLOCK_SIZE {
            let data = unsafe {
                let ptr = ciphertext.as_ptr() as *const [u8; BLOCK_SIZE];
                &*ptr
            };
            plaintext.extend(self.decrypt_block(data));

            Ok(())
        } else {
            Err(CipherError::InvalidBlockSize {
                real: ciphertext.len(),
                target: BLOCK_SIZE,
            })
        }
    }
}

mod aes;
pub use aes::{AES, AES128, AES192, AES256};
