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
    fn encrypt<R: Read, W: Write>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), CipherError>;

    /// `(nonce, in_data, associated_data) ---认证解密---> out_data` <br>
    /// 返回从`in_data`和`out_data`读入写入数据的字节长度
    fn decrypt<R: Read, W: Write>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), CipherError>;
}

mod ccm;
pub use ccm::{AES128Ccm, AES192Ccm, AES256Ccm, AESCcm, CCM};
