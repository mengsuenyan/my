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

pub trait BlockEncryptX {
    fn block_size_x(&self) -> usize;

    fn encrypt_block_x(
        &self,
        plaintext: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), CipherError>;
}

pub trait BlockDecryptX {
    fn block_size_x(&self) -> usize;

    fn decrypt_block_x(
        &self,
        ciphertext: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CipherError>;
}

pub trait BlockCipherX: BlockEncryptX + BlockDecryptX {}

impl<T> BlockCipherX for T where T: BlockEncryptX + BlockDecryptX {}

impl<T: BlockEncryptX> BlockEncryptX for Box<T> {
    fn block_size_x(&self) -> usize {
        self.deref().block_size_x()
    }

    fn encrypt_block_x(
        &self,
        plaintext: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        self.deref().encrypt_block_x(plaintext, ciphertext)
    }
}

impl<T: BlockDecryptX> BlockDecryptX for Box<T> {
    fn block_size_x(&self) -> usize {
        self.deref().block_size_x()
    }

    fn decrypt_block_x(
        &self,
        ciphertext: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        self.deref().decrypt_block_x(ciphertext, plaintext)
    }
}

impl BlockEncryptX for Box<dyn BlockCipherX + Send + Sync + 'static> {
    fn block_size_x(&self) -> usize {
        BlockEncryptX::block_size_x(self.deref())
    }

    fn encrypt_block_x(
        &self,
        plaintext: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        self.deref().encrypt_block_x(plaintext, ciphertext)
    }
}

impl BlockDecryptX for Box<dyn BlockCipherX + Send + Sync + 'static> {
    fn block_size_x(&self) -> usize {
        BlockDecryptX::block_size_x(self.deref())
    }

    fn decrypt_block_x(
        &self,
        ciphertext: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        self.deref().decrypt_block_x(ciphertext, plaintext)
    }
}

mod aes;
use std::ops::Deref;

pub use aes::{AES, AES128, AES192, AES256};
mod sm4;
pub use crate::rsa::{OAEPDecrypt, OAEPEncrypt, PKCS1Decrypt, PKCS1Encrypt};
use crate::{CipherError, Decrypt, Encrypt};
pub use sm4::SM4;
use utils::Block;

macro_rules! impl_block_cipher_x {
    ($NAME1: ty, $($NAME2: ty),+) => {
        impl_block_cipher_x!($NAME1);
        impl_block_cipher_x!($($NAME2),+);
    };
    ($NAME: ty) => {
        impl BlockEncryptX for $NAME {
            fn block_size_x(&self) -> usize {
                Self::BLOCK_SIZE
            }

            fn encrypt_block_x(
                &self,
                plaintext: &[u8],
                ciphertext: &mut Vec<u8>,
            ) -> Result<(), CipherError> {
                if plaintext.len() != Self::BLOCK_SIZE {
                    return Err(CipherError::InvalidBlockSize {
                        target: Self::BLOCK_SIZE,
                        real: plaintext.len(),
                    });
                }

                let block = Block::as_arr_ref_uncheck(plaintext);
                ciphertext.extend(self.encrypt_block(block));

                Ok(())
            }
        }

        impl BlockDecryptX for $NAME {
            fn block_size_x(&self) -> usize {
                Self::BLOCK_SIZE
            }

            fn decrypt_block_x(
                &self,
                ciphertext: &[u8],
                plaintext: &mut Vec<u8>,
            ) -> Result<(), CipherError> {
                if ciphertext.len() != Self::BLOCK_SIZE {
                    return Err(CipherError::InvalidBlockSize {
                        target: Self::BLOCK_SIZE,
                        real: ciphertext.len(),
                    });
                }

                let block = Block::as_arr_ref_uncheck(ciphertext);
                plaintext.extend(self.decrypt_block(block));

                Ok(())
            }
        }
    };
}

impl<T: BlockEncryptX> Encrypt for T {
    fn encrypt(&self, plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), CipherError> {
        self.encrypt_block_x(plaintext, ciphertext)
    }
}

impl<T: BlockDecryptX> Decrypt for T {
    fn decrypt(&self, ciphertext: &[u8], plaintext: &mut Vec<u8>) -> Result<(), CipherError> {
        self.decrypt_block_x(ciphertext, plaintext)
    }
}

// rust支持`impl<T, const N: usize> Encrypt for T where T: BlockEncrypt<N> {...}`之后
// 修改为这种形式
impl_block_cipher_x!(SM4, AES, AES128, AES192, AES256);
