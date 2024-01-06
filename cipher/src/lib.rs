mod error;
pub use error::CipherError;

pub use rand::{DefaultRand, Rand};

pub mod block_cipher;
pub use block_cipher::{
    BlockCipher, BlockCipherX, BlockDecrypt, BlockDecryptX, BlockEncrypt, BlockEncryptX,
};

pub mod stream_cipher;
pub use stream_cipher::{StreamCipher, StreamCipherFinish, StreamDecrypt, StreamEncrypt};

pub mod cipher_mode;
pub use cipher_mode::BlockPadding;

pub mod mac;
pub use mac::MAC;

pub mod ae;
pub use ae::AuthenticationCipher;

pub mod builder;
pub mod dss;
pub mod rsa;

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

pub trait Sign {
    fn sign(&self, msg: &[u8], sign: &mut Vec<u8>) -> Result<(), CipherError>;
}

pub trait Verify {
    fn verify(&self, msg: &[u8], sign: &[u8]) -> Result<(), CipherError>;
}

pub trait Signer: Sign + Verify {}
