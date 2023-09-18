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

mod aes;
pub use aes::{AES, AES128, AES192, AES256};
