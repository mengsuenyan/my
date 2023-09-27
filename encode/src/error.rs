use std::fmt::{Display, Formatter};
use std::io::Error;

#[derive(Debug)]
pub enum EncodeError {
    IoErr(Error),
    InvalidBaseCodeInDec(char),
    InvalidLenInDec(usize),
}

impl Display for EncodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::IoErr(io) => f.write_fmt(format_args!("{}", io)),
            EncodeError::InvalidLenInDec(len) => {
                f.write_fmt(format_args!("Invalid data length `{}` in the decode", len))
            }
            EncodeError::InvalidBaseCodeInDec(code) => f.write_fmt(format_args!(
                "Invalid base encode character `{}({:#x})`",
                code, *code as u64
            )),
        }
    }
}

impl std::error::Error for EncodeError {}

impl From<Error> for EncodeError {
    fn from(value: Error) -> Self {
        Self::IoErr(value)
    }
}
