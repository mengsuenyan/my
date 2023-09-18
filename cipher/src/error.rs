use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum CipherError {
    /// 不合法分组大小
    InvalidBlockSize {
        target: usize,
        real: usize,
    },

    /// 不合法的密钥长度
    InvalidKeySize {
        target: Option<usize>,
        real: usize,
    },

    IOError(std::io::Error),

    /// 解填充错误
    UnpaddingNotMatch(String),

    /// 正处于加密或解密过程中, ture加密中, false解密中
    BeWorking(bool),

    /// 未设置初始化向量
    NotSetInitialVec,

    Other(String),
}

impl Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBlockSize { target, real } => f.write_fmt(format_args!(
                "Invalid block data size `{real}` not match to target size `{target}`"
            )),
            CipherError::InvalidKeySize { target, real } => match target {
                Some(target) => f.write_fmt(format_args!(
                    "Invalid key size `{real}` not match to target size `{target}`"
                )),
                None => f.write_fmt(format_args!(
                    "Invalid key size '{real}' not match to all target size"
                )),
            },
            CipherError::IOError(io_err) => f.write_fmt(format_args!("{}", io_err)),
            CipherError::UnpaddingNotMatch(name) => {
                f.write_fmt(format_args!("unpadding failed by the `{name}`"))
            }
            CipherError::BeWorking(is_encrypt) => f.write_fmt(format_args!(
                "Currently during in the `{}` process",
                if *is_encrypt { "encrypt" } else { "decrypt" }
            )),
            CipherError::NotSetInitialVec => f.write_str("Not set initial vector"),
            CipherError::Other(other) => f.write_str(other.as_str()),
        }
    }
}

impl Error for CipherError {}

impl From<std::io::Error> for CipherError {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}
