use std::io::{Read, Write};

pub trait Encode {
    /// 返回读和写字节数
    fn encode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError>;
}

pub trait Decode {
    fn decode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError>;
}

pub mod base;
mod error;
pub use error::EncodeError;
