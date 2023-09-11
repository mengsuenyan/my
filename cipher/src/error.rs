use std::{error::Error, fmt::Display};

#[derive(Clone, Debug)]
pub enum CipherError {
    /// 不合法分组大小
    InvalidBlockSize { target: usize, real: usize },

    /// 不合法的密钥长度
    InvalidKeySize { target: usize, real: usize },
}

impl Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBlockSize { target, real } => f.write_fmt(format_args!(
                "Invalid block data size `{real}` not match to target size `{target}`"
            )),
            CipherError::InvalidKeySize { target, real } => {
                f.write_fmt(format_args!("Invalid key size `{real}` not match to target size `{target}`"))
            },
        }
    }
}

impl Error for CipherError {}
