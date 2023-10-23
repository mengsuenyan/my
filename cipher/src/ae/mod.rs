//! # Authenticated Encryption (AE)
//!
//!
//! 认证加密: Authentication + Confidentiality,
//!
use crate::CipherError;
use std::io::{Read, Write};

/// 认证加密: 数据加密+消息认证 <br>
pub trait AuthenticationCipher {
    /// MAC字节长度
    fn mac_size(&self) -> usize;

    /// `(nonce, in_data, associated_data) ---认证加密---> out_data` <br>
    /// 返回从`in_data`和`out_data`读入写入数据的字节长度
    fn auth_encrypt<R: Read, W: Write>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), CipherError>;

    /// `(nonce, in_data, associated_data) ---认证解密---> out_data` <br>
    /// 返回从`in_data`和`out_data`读入写入数据的字节长度
    fn auth_decrypt<R: Read, W: Write>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), CipherError>;
}

pub trait AuthenticationCipherX {
    fn mac_size_x(&self) -> usize;

    fn auth_encrypt_x(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError>;
    fn auth_decrypt_x(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError>;
}

impl<T> AuthenticationCipherX for T
where
    T: AuthenticationCipher,
{
    fn mac_size_x(&self) -> usize {
        self.mac_size()
    }

    fn auth_encrypt_x(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        mut in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        self.auth_encrypt(nonce, associated_data, &mut in_data, out_data)
    }

    fn auth_decrypt_x(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        mut in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        self.auth_decrypt(nonce, associated_data, &mut in_data, out_data)
    }
}

mod ccm;
pub use ccm::{AES128Ccm, AES192Ccm, AES256Ccm, AESCcm, CCM};

mod gcm;
pub use gcm::{
    AES128Gcm, AES128GcmStream, AES192Gcm, AES192GcmStream, AES256Gcm, AES256GcmStream, AESGcm,
    AESGcmStream, GcmStream, GCM,
};
