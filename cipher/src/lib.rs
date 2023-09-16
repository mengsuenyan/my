mod error;
pub use error::CipherError;

pub mod block_cipher;
pub use block_cipher::{BlockCipher, BlockCipherWrapper, BlockDecrypt, BlockEncrypt};

pub mod stream_cipher;

pub mod cipher_mode;

pub trait Encrypt {
    fn encrypt(&self, plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), CipherError>;
}

pub trait Decrypt {
    fn decrypt(&self, ciphertext: &[u8], plaintext: &mut Vec<u8>) -> Result<(), CipherError>;
}

pub trait Cipher: Encrypt + Decrypt {}

impl<T> Cipher for T where T: Encrypt + Decrypt {}
