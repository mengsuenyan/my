use crate::{CipherError, Decrypt, Encrypt};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

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

pub trait StreamDecrypt: Sized {
    /// 返回(读, 写)字节数
    fn stream_decrypt<'a, R: Read, W: Write>(
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

impl<T> Encrypt for Mutex<T>
where
    T: StreamEncrypt,
{
    fn encrypt(&self, mut plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), CipherError> {
        match self.lock() {
            Ok(mut c) => {
                let finish = c.stream_encrypt(&mut plaintext, ciphertext)?;
                let _l = finish.finish(ciphertext)?;
                Ok(())
            }
            Err(e) => Err(CipherError::Other(format!("{e}"))),
        }
    }
}

impl<T> Decrypt for Mutex<T>
where
    T: StreamDecrypt,
{
    fn decrypt(&self, mut ciphertext: &[u8], plaintext: &mut Vec<u8>) -> Result<(), CipherError> {
        match self.lock() {
            Ok(mut c) => {
                let finish = c.stream_decrypt(&mut ciphertext, plaintext)?;
                let _l = finish.finish(plaintext)?;
                Ok(())
            }
            Err(e) => Err(CipherError::Other(format!("{e}"))),
        }
    }
}

pub trait StreamCipher: StreamEncrypt + StreamDecrypt {}

impl<T: StreamEncrypt + StreamDecrypt> StreamCipher for T {}

pub trait StreamEncryptX {
    fn stream_encrypt_x(
        &mut self,
        in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError>;

    fn stream_encrypt_finish_x(
        &mut self,
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError>;
}

pub trait StreamDecryptX {
    fn stream_decrypt_x(
        &mut self,
        in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError>;
    fn stream_decrypt_finish_x(
        &mut self,
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError>;
}

pub trait StreamCipherX: StreamEncryptX + StreamDecryptX {}

impl<T> StreamCipherX for T where T: StreamEncryptX + StreamDecryptX {}

impl<T> StreamEncryptX for Arc<Mutex<T>>
where
    T: StreamEncrypt,
{
    fn stream_encrypt_x(
        &mut self,
        in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        self.lock()
            .map_err(|e| CipherError::Other(format!("{e}")))?
            .stream_encrypt_x(in_data, out_data)
    }
    fn stream_encrypt_finish_x(
        &mut self,
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        self.lock()
            .map_err(|e| CipherError::Other(format!("{e}")))?
            .stream_encrypt_finish_x(out_data)
    }
}

impl<T> StreamEncryptX for T
where
    T: StreamEncrypt,
{
    fn stream_encrypt_x(
        &mut self,
        mut in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        let x = self.stream_encrypt(&mut in_data, out_data)?;
        Ok((x.read_len(), x.write_len()))
    }

    fn stream_encrypt_finish_x(
        &mut self,
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        let mut empty = [0u8; 0].as_slice();
        let x = self.stream_encrypt(&mut empty, out_data)?;
        let len = (x.read_len(), x.write_len());
        let x = x.finish(out_data)?;
        Ok((x.0 + len.0, x.1 + len.1))
    }
}

impl<T> StreamDecryptX for Arc<Mutex<T>>
where
    T: StreamDecrypt,
{
    fn stream_decrypt_x(
        &mut self,
        in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        self.lock()
            .map_err(|e| CipherError::Other(format!("{e}")))?
            .stream_decrypt_x(in_data, out_data)
    }
    fn stream_decrypt_finish_x(
        &mut self,
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        self.lock()
            .map_err(|e| CipherError::Other(format!("{e}")))?
            .stream_decrypt_finish_x(out_data)
    }
}

impl<T> StreamDecryptX for T
where
    T: StreamDecrypt,
{
    fn stream_decrypt_x(
        &mut self,
        mut in_data: &[u8],
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        let x = self.stream_decrypt(&mut in_data, out_data)?;
        Ok((x.read_len(), x.write_len()))
    }

    fn stream_decrypt_finish_x(
        &mut self,
        out_data: &mut Vec<u8>,
    ) -> Result<(usize, usize), CipherError> {
        let mut empty = [0u8; 0].as_slice();
        let x = self.stream_decrypt(&mut empty, out_data)?;
        let len = (x.read_len(), x.write_len());
        let x = x.finish(out_data)?;
        Ok((x.0 + len.0, x.1 + len.1))
    }
}

pub mod zuc;
pub use crate::ae::{AES128GcmStream, AES192GcmStream, AES256GcmStream, AESGcmStream, GcmStream};
pub use crate::cipher_mode;
pub use crate::rsa::{OAEPDecryptStream, OAEPEncryptStream, PKCS1DecryptSteam, PKCS1EncryptStream};
