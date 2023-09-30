//! # 祖冲之序列密码算法
//!
//! - 包含三个部分:
//!   - 密钥流的生成;
//!   - 流加密;
//!   - 消息认证码生成;
//!

mod cipher;
pub use cipher::ZUC;
mod key;
pub use key::ZUCKey;
mod mac;
pub use mac::ZUCMac;

/// ZUCStdMac标准规范输出4字节的MAC
pub type ZUCStdMac = ZUCMac<4>;
