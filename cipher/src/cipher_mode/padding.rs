use crate::{BlockCipher, CipherError};
use std::cmp::Ordering;

pub trait BlockPadding {
    /// 填充到`padding_len`字节长度
    fn new(padding_len: usize) -> Self;

    fn padding(&self, buf: &mut Vec<u8>);

    fn unpadding(&self, buf: &mut Vec<u8>) -> Result<(), CipherError>;

    /// 最长补几个块
    fn max_padding_blocks(&self) -> usize;
}

impl<T> BlockPadding for Box<T>
where
    T: BlockPadding,
{
    /// 对齐到`padding_len`字节长度
    fn new(padding_len: usize) -> Self {
        Box::new(T::new(padding_len))
    }

    fn padding(&self, buf: &mut Vec<u8>) {
        (**self).padding(buf)
    }

    fn unpadding(&self, buf: &mut Vec<u8>) -> Result<(), CipherError> {
        (**self).unpadding(buf)
    }

    fn max_padding_blocks(&self) -> usize {
        (**self).max_padding_blocks()
    }
}

/// 填充`0x80`, 再补充若干个`0x00`以使得填充后的数据字节长度是分组长度的整数倍. <br>
#[derive(Copy, Clone, Debug)]
pub struct DefaultPadding {
    block_size: usize,
}

impl DefaultPadding {
    pub fn from_block_cipher<E: BlockCipher<N>, const N: usize>(_cipher: &E) -> Self {
        Self::new(N)
    }
}

impl BlockPadding for DefaultPadding {
    fn new(block_size: usize) -> Self {
        Self { block_size }
    }

    fn padding(&self, buf: &mut Vec<u8>) {
        buf.push(0x80);
        let len = buf.len();

        match self.block_size.cmp(&len) {
            Ordering::Less => buf.resize(len + (self.block_size - (len % self.block_size)), 0),
            Ordering::Equal => {}
            Ordering::Greater => buf.resize(self.block_size, 0),
        }
    }

    fn unpadding(&self, buf: &mut Vec<u8>) -> Result<(), CipherError> {
        let mut padding_len = 0;
        for &ele in buf.iter().rev() {
            if ele == 0 {
                padding_len += 1;
            } else if ele == 0x80 {
                buf.truncate(buf.len() - padding_len - 1);
                return Ok(());
            }
        }

        Err(CipherError::UnpaddingNotMatch("DefaultPadding".to_string()))
    }

    fn max_padding_blocks(&self) -> usize {
        1
    }
}

#[derive(Copy, Clone, Debug)]
pub struct EmptyPadding;

impl BlockPadding for EmptyPadding {
    fn new(_padding_len: usize) -> Self {
        Self
    }

    fn padding(&self, _buf: &mut Vec<u8>) {}

    fn unpadding(&self, _buf: &mut Vec<u8>) -> Result<(), CipherError> {
        Ok(())
    }

    fn max_padding_blocks(&self) -> usize {
        0
    }
}
