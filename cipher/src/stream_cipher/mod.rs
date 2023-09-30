use crate::{CipherError, Decrypt, Encrypt};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::marker::PhantomData;

type FinishFn<'a, T, W> = Box<dyn FnOnce(&'a mut T, &mut W) -> Result<usize, CipherError>>;

pub struct StreamCipherFinish<'a, T, R: Read, W: Write> {
    sf: &'a mut T,
    in_len: usize,
    out_len: usize,
    finish: FinishFn<'a, T, W>,
    read: PhantomData<R>,
}

impl<'a, T, R, W> StreamCipherFinish<'a, T, R, W>
where
    W: Write,
    R: Read,
{
    /// `len`: (已经读入的数据字节长度, 已经写入的字节长度)
    pub fn new<F>(sf: &'a mut T, len: (usize, usize), finish: F) -> Self
    where
        F: 'static + FnOnce(&'a mut T, &mut W) -> Result<usize, CipherError>,
    {
        Self {
            sf,
            in_len: len.0,
            out_len: len.1,
            finish: Box::new(finish),
            read: PhantomData,
        }
    }

    /// 返回(流读入的字节大小, 流写入的字节大小)
    pub fn finish(self, out_data: &mut W) -> Result<(usize, usize), CipherError> {
        let sf = self.sf;
        let finish = self.finish;
        let s = finish(sf, out_data)?;
        Ok((self.in_len, self.out_len + s))
    }

    /// 已从输入流中读取的字节数
    pub const fn read_len(&self) -> usize {
        self.in_len
    }

    /// 已写入到输出流中的字节数
    pub const fn write_len(&self) -> usize {
        self.out_len
    }
}

impl<'a, T, R, W> StreamCipherFinish<'a, T, R, W>
where
    W: Write,
    R: Read,
    T: StreamEncrypt,
{
    pub fn stream_encrypt(self, in_data: &'a mut R, out_data: &mut W) -> Result<Self, CipherError> {
        let mut s = self.sf.stream_encrypt(in_data, out_data)?;
        s.in_len += self.in_len;
        s.out_len += self.out_len;
        Ok(s)
    }
}

impl<'a, T, R, W> StreamCipherFinish<'a, T, R, W>
where
    W: Write,
    R: Read,
    T: StreamDecrypt,
{
    pub fn stream_decrypt(self, in_data: &'a mut R, out_data: &mut W) -> Result<Self, CipherError> {
        let mut s = self.sf.stream_decrypt(in_data, out_data)?;
        s.in_len += self.in_len;
        s.out_len += self.out_len;
        Ok(s)
    }
}

pub trait StreamEncrypt: Sized {
    fn stream_encrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError>;
}

impl<T> Encrypt for RefCell<T>
where
    T: StreamEncrypt,
{
    fn encrypt(&self, mut plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), CipherError> {
        let mut sf = self.borrow_mut();
        let s = sf.stream_encrypt(&mut plaintext, ciphertext)?;
        let _l = s.finish(ciphertext)?;
        Ok(())
    }
}

pub trait StreamDecrypt: Sized {
    /// 返回(读, 写)字节数
    fn stream_decrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError>;
}

impl<T> Decrypt for RefCell<T>
where
    T: StreamDecrypt,
{
    fn decrypt(&self, mut ciphertext: &[u8], plaintext: &mut Vec<u8>) -> Result<(), CipherError> {
        let mut sf = self.borrow_mut();
        let s = sf.stream_decrypt(&mut ciphertext, plaintext)?;
        let _l = s.finish(plaintext)?;
        Ok(())
    }
}

pub trait StreamCipher: StreamEncrypt + StreamDecrypt {}

impl<T: StreamEncrypt + StreamDecrypt> StreamCipher for T {}

pub mod zuc;
