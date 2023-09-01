use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum MyError {
    #[error("Invalid Encode Head: {0:#x}")]
    InvalidEncodeHead(u64),

    #[error("Invalid Encode Type: {0:#x}")]
    InvalidEncodeType(u64),

    #[error("Invalid data len `{0}` bytes to conver to EncodeData")]
    InvalidEncodeDataLen(usize),

    #[error("Invalid encode data `{data}` in the `{idx}`th bytes")]
    InvaidEncodeData { idx: usize, data: u8 },

    #[error("The path {0} not exist")]
    PathNotExist(String),

    #[error("{0}")]
    PathOtherErr(String),

    #[error("{0}")]
    NotSupport(String),

    #[error("{0}")]
    JsonParseFailed(String),

    #[error("{0}")]
    ChangeDirFailed(String),

    #[error("{0}")]
    RegexFailed(String),

    #[error("{0}")]
    GitNotFoundAddr(String),

    #[error("{0}")]
    GitFailed(String),
}
