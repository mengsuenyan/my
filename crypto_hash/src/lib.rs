use std::io::Write;

mod output;
pub use output::Output;

mod error;
pub use error::HashError;

pub mod cshake;
pub mod keccak;
pub mod sha2;
pub mod sha3;

/// 哈希算法实现该trait, 计算消息的摘要. 可直接调用`Digest::digest(msg)`生成消息的摘要, 或者通过`Write` trait将数据更新
/// 到`self`中后使用`self.finalize()`生成消息摘要.
///
/// 可用于如下安全应用中:
/// - 数据一致性验证;
/// - 参与数字签名的生成和验证;
/// - 密钥派生;
/// - 伪随机数生成;
pub trait Digest: Write + Sized {
    /// 哈希算法每次按块处理消息的块的位长度
    const BLOCK_BITS: usize;
    /// 哈希算法将每个块按该位长度划分为若干个单词
    const WORD_BITS: usize;
    /// 哈希算法生成的摘要的位长度
    const DIGEST_BITS: usize;

    /// 生成消息摘要
    fn digest(msg: &[u8]) -> Output<Self>;

    /// 生成消息摘要
    fn finalize(self) -> Output<Self>;

    /// 重置哈希算法到初始化状态
    fn reset(&mut self);
}

/// Extendable-output function <br>
pub trait XOF: Write {
    const BLOCK_BITS: usize;
    const WORD_BITS: usize;
    // 期望输出摘要的字节大小
    fn desired_len(&self) -> usize;

    fn finalize(self) -> Vec<u8>;

    fn reset(&mut self);
}
