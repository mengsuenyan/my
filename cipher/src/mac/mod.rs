//! # Message Authentication Code(MAC)
//!
//! Authentication: 验证消息的完整性+身份;
//!
use std::io::Write;

/// marker for Message Authentication Code <br>
///
/// 以某个密钥生成指定长度的消息摘要, 用于验证消息的完整性和身份验证(拥有该密钥的身份者才能够生成该摘要)
pub trait MAC: Write {
    /// 块字节大小
    const BLOCK_SIZE: usize;
    /// 摘要大小
    const DIGEST_SIZE: usize;

    /// 获取本轮的MAC
    fn mac(&mut self) -> Vec<u8>;

    /// 重置MAC到初始化状态
    fn reset(&mut self);
}

pub trait MACx: Write {
    fn block_size_x(&self) -> usize;
    fn digest_size_x(&self) -> usize;

    fn mac(&mut self) -> Vec<u8>;

    fn reset(&mut self);
}

impl<T> MACx for T
where
    T: MAC,
{
    fn block_size_x(&self) -> usize {
        Self::BLOCK_SIZE
    }
    fn digest_size_x(&self) -> usize {
        Self::DIGEST_SIZE
    }
    fn mac(&mut self) -> Vec<u8> {
        self.mac()
    }
    fn reset(&mut self) {
        self.reset()
    }
}

mod cmac;
pub use cmac::CMAC;

mod hmac;
pub use hmac::HMAC;
