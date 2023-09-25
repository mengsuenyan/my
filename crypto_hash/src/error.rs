use std::{error::Error, fmt::Display};

#[derive(Clone, Debug)]
pub enum HashError {
    /// 实际字节长度`real`和目标字节长度`target`不匹配
    MismatchingByteLen {
        target: usize,
        real: usize,
    },
    Keccak(String),
}

impl Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashError::MismatchingByteLen { target, real } => f.write_fmt(format_args!(
                "real byte length `{real}` not match to target byte length `{target}`"
            )),
            HashError::Keccak(s) => f.write_str(s.as_str()),
        }
    }
}

impl Error for HashError {}
