mod error;
pub use error::CipherError;

pub mod rand;
pub use rand::Rand;

pub mod block_cipher;
pub use block_cipher::{BlockCipher, BlockDecrypt, BlockEncrypt};

pub mod stream_cipher;
pub use stream_cipher::{StreamCipher, StreamCipherFinish, StreamDecrypt, StreamEncrypt};

pub mod cipher_mode;

pub trait Encrypt {
    // 写入ciphertext之前不清空
    fn encrypt(&self, plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), CipherError>;
}

pub trait Decrypt {
    // 写入plaintext之前不清空
    fn decrypt(&self, ciphertext: &[u8], plaintext: &mut Vec<u8>) -> Result<(), CipherError>;
}

pub trait Cipher: Encrypt + Decrypt {}

impl<T> Cipher for T where T: Encrypt + Decrypt {}
