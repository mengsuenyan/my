use std::error::Error;

/// 分组加密
pub trait BlockCipher {
    type Err: Error;

    /// 分组字节大小
    const BLOCK_SIZE: usize;

    /// 将明文`plaintext`加密成密文`ciphertext`
    fn encrypt(&self, plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), Self::Err>;

    /// 将密文`ciphertext`解密为明文`ciphertext`
    fn decrypt(&self, ciphertext: &[u8], plaintext: &mut Vec<u8>) -> Result<(), Self::Err>;
}

mod aes;
pub use aes::{AES, AES128, AES192, AES256};
