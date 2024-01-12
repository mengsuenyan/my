//! # Message Authentication Code(MAC)
//!
//! Authentication: 验证消息的完整性+身份;
//!
use std::io::Write;

/// marker for Message Authentication Code <br>
///
/// 以某个密钥生成指定长度的消息摘要, 用于验证消息的完整性和身份验证(拥有该密钥的身份者才能够生成该摘要)
pub trait MAC: Write {
    fn block_size_x(&self) -> usize;
    fn digest_size_x(&self) -> usize;

    fn mac(&mut self) -> Vec<u8>;

    fn reset(&mut self);
}

mod cmac;
pub use cmac::CMAC;

mod hmac;
pub use hmac::HMAC;

mod kmac;
pub use kmac::{KMAC, KMACXof};

pub use crate::stream_cipher::zuc::{ZUCMac, ZUCStdMac};
