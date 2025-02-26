//! ## The Cipher Block Chaining Mode(CBC)
//!
//! 给定初始向量IV, IV可以不保密, 但是**它必须是不可预测的(unpredictable)**. <br>
//!
//! $$
//! C_1 = Encrypt(P_1 \xor IV); C_j = Encrypt(P_j \xor C_{j-1}), j = 2...n
//!
//! P_1 = Decrypt(C_1) \xor IV; P_j = Decrypt(C_j) \xor C_{j-1}, j = 2...n
//! $$
//!
//! 在CBC模式中, 加密每个明文块依赖前一个密文输出, 故Encrypt无法并行. 但Decrypt是可以并行的. <br>
//! <br>
//!

use crate::block_cipher::{AES, AES128, AES192, AES256};
use crate::cipher_mode::BlockPadding;
use crate::{
    BlockDecryptX, BlockEncryptX, CipherError, StreamCipherFinish, StreamDecrypt, StreamEncrypt,
};
use std::io::{Read, Write};
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

/// Cipher Block Chaining Mode(CBC) <br>
///
/// 给定初始向量IV, IV可以不保密, 但是**它必须是不可预测的(unpredictable)**. 因此, 使用过后再次进行加解密时需调用`self.set_iv`设置新的`IV`. <br>
pub struct CBC<P, E> {
    //缓存输入数据
    data: Vec<u8>,
    //缓存输出数据
    out_buf: Vec<u8>,
    /// 初始化向量
    iv: Vec<u8>,
    cipher: E,
    padding: P,
    is_encrypt: Option<bool>,
}

def_type_block_cipher!(
    CBC,
    [AESCbc, AES],
    [AES128Cbc, AES128],
    [AES192Cbc, AES192],
    [AES256Cbc, AES256]
);

impl_set_working_flag!(CBC);

impl<P, E> CBC<P, E> {
    pub(super) fn clear_resource(&mut self) {
        self.is_encrypt = None;
        self.data.clear();
        self.out_buf.clear();
        self.iv.clear();
    }

    fn check_iv(&self) -> Result<(), CipherError> {
        if self.iv.is_empty() {
            Err(CipherError::NotSetInitialVec)
        } else {
            Ok(())
        }
    }

    pub(super) fn get_cipher(&self) -> &E {
        &self.cipher
    }
}

impl<P, E> CBC<P, E>
where
    P: BlockPadding,
    E: BlockEncryptX,
{
    pub fn new(cipher: E, iv: Vec<u8>) -> Result<Self, CipherError> {
        if iv.len() != cipher.block_size_x() {
            return Err(CipherError::InvalidKeySize {
                real: iv.len(),
                target: Some(cipher.block_size_x()),
            });
        }

        Ok(Self {
            data: Vec::with_capacity(cipher.block_size_x()),
            out_buf: vec![],
            iv,
            padding: P::new(cipher.block_size_x()),
            cipher,
            is_encrypt: None,
        })
    }

    pub fn set_padding(&mut self, padding: P) {
        self.padding = padding;
    }

    pub fn set_iv(&mut self, mut iv: Vec<u8>) -> Result<(), CipherError> {
        if iv.len() != self.cipher.block_size_x() {
            return Err(CipherError::InvalidKeySize {
                real: iv.len(),
                target: Some(self.cipher.block_size_x()),
            });
        }

        self.iv.clear();
        self.iv.append(&mut iv);
        Ok(())
    }
}

impl<P, E> CBC<P, E>
where
    E: BlockEncryptX,
    P: BlockPadding,
{
    // iv即是输入也是输出
    fn encrypt_inner(
        cipher: &E,
        block: &[u8],
        buf: &mut Vec<u8>,
        iv: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        buf.clear();
        iv.iter()
            .zip(block.iter())
            .for_each(|(a, b)| buf.push(a ^ b));
        iv.clear();
        cipher.encrypt_block_x(buf.as_slice(), iv)?;
        Ok(())
    }
}

impl<P, E> CBC<P, E>
where
    E: BlockDecryptX,
    P: BlockPadding,
{
    // 解密输出到out_buf, 并更新iv
    fn decrypt_inner(
        cipher: &E,
        block: &[u8],
        iv: &mut Vec<u8>,
        out_buf: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        cipher.decrypt_block_x(block, out_buf)?;
        iv.iter()
            .rev()
            .zip(out_buf.iter_mut().rev())
            .for_each(|(&a, b)| *b ^= a);
        iv.clear();
        iv.extend_from_slice(block);
        Ok(())
    }
}

#[cfg(feature = "sec-zeroize")]
impl<P, E> Zeroize for CBC<P, E>
where
    E: Zeroize,
{
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.iv.zeroize();
    }
}

impl<P, E> StreamEncrypt for CBC<P, E>
where
    E: BlockEncryptX,
    P: BlockPadding,
{
    fn stream_encrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(true)?;
        self.check_iv()?;

        let (mut buf, mut out_len, n) = (Vec::with_capacity(2048), 0, self.cipher.block_size_x());
        buf.extend(self.data.iter());
        self.data.clear();
        let in_len = in_data.read_to_end(&mut buf).map_err(CipherError::from)?;

        let mut itr = buf.chunks_exact(n);
        for chunk in &mut itr {
            // 这里把self.data作为缓存使用
            Self::encrypt_inner(&self.cipher, chunk, &mut self.data, &mut self.iv)?;
            out_data
                .write_all(self.iv.as_slice())
                .map_err(CipherError::from)?;
            out_len += n;
        }
        self.data.clear();
        self.data.extend(itr.remainder());

        let s = StreamCipherFinish::new(self, (in_len, out_len), |sf, outdata: &mut W| {
            sf.padding.padding(sf.data.as_mut());

            let n = sf.cipher.block_size_x();
            let (mut itr, mut s, mut buf) = (sf.data.chunks_exact(n), 0, Vec::with_capacity(n));
            for chunk in &mut itr {
                Self::encrypt_inner(&sf.cipher, chunk, &mut buf, &mut sf.iv)?;
                outdata
                    .write_all(sf.iv.as_slice())
                    .map_err(CipherError::from)?;
                s += n;
            }

            let len = itr.remainder().len();
            sf.clear_resource();
            if len > 0 {
                Err(CipherError::InvalidBlockSize {
                    target: n,
                    real: len,
                })
            } else {
                Ok(s)
            }
        });

        Ok(s)
    }
}

impl<P, E> StreamDecrypt for CBC<P, E>
where
    E: BlockDecryptX,
    P: BlockPadding,
{
    fn stream_decrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(false)?;
        self.check_iv()?;

        let n = self.cipher.block_size_x();
        let padding_blocks = self.padding.max_padding_blocks().max(1);
        let (tgt_len, mut out_len, mut buf) = (
            (padding_blocks.max(32) + padding_blocks) * n,
            0,
            Vec::with_capacity(2048),
        );

        buf.extend(self.data.iter());
        let in_len = in_data.read_to_end(&mut buf).map_err(CipherError::from)?;
        let mut itr = buf.chunks_exact(n);
        for chunk in &mut itr {
            Self::decrypt_inner(&self.cipher, chunk, &mut self.iv, &mut self.out_buf)?;
            if self.out_buf.len() > tgt_len {
                let bound = self.out_buf.len() - n;
                out_data
                    .write_all(&self.out_buf[..bound])
                    .map_err(CipherError::from)?;
                self.out_buf.rotate_right(n);
                self.out_buf.truncate(n);
                out_len += bound;
            }
        }
        self.data.clear();
        self.data.extend(itr.remainder());

        let s = StreamCipherFinish::new(self, (in_len, out_len), |sf, outdata: &mut W| {
            let n = sf.cipher.block_size_x();
            let (mut itr, mut buf) = (sf.data.chunks_exact(n), Vec::with_capacity(n));
            for chunk in &mut itr {
                Self::decrypt_inner(&sf.cipher, chunk, &mut buf, &mut sf.iv)?;
                sf.out_buf.extend_from_slice(sf.iv.as_slice());
            }

            let len = itr.remainder().len();
            if len > 0 {
                sf.clear_resource();
                Err(CipherError::InvalidBlockSize {
                    target: n,
                    real: len,
                })
            } else {
                sf.padding.unpadding(&mut sf.out_buf)?;
                let last_len = sf.out_buf.len();

                outdata
                    .write_all(sf.out_buf.as_slice())
                    .map_err(CipherError::from)?;
                sf.clear_resource();
                Ok(last_len)
            }
        });

        Ok(s)
    }
}

#[cfg(test)]
pub(in crate::cipher_mode) mod tests {
    use super::{StreamDecrypt, StreamEncrypt};
    use crate::block_cipher::AES;
    use crate::cipher_mode::{AESCbc, DefaultPadding, EmptyPadding};
    use crate::{BlockCipher, BlockPadding, Decrypt, Encrypt};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::cell::RefCell;

    /// (key, iv, plaintext, ciphertext)
    pub(in crate::cipher_mode) fn cases() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let cases = [
            (
                "2b7e151628aed2a6abf7158809cf4f3c",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
            ),
            (
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd"
                ),
            (
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
                )
        ];

        cases
            .into_iter()
            .map(|(key, iv, pt, ct)| {
                let (key, mut iv, pt, ct) = (
                    BigUint::from_str_radix(key, 16).unwrap().to_bytes_be(),
                    BigUint::from_str_radix(iv, 16).unwrap().to_bytes_be(),
                    BigUint::from_str_radix(pt, 16).unwrap().to_bytes_be(),
                    BigUint::from_str_radix(ct, 16).unwrap().to_bytes_be(),
                );

                let l = iv.len();
                while iv.len() < AES::BLOCK_SIZE {
                    iv.resize(AES::BLOCK_SIZE, 0);
                    iv.rotate_right(AES::BLOCK_SIZE - l);
                }

                (key, iv, pt, ct)
            })
            .collect()
    }

    #[test]
    fn cbc_aes_empty_padding() {
        for (i, (key, iv, pt, ct)) in cases().into_iter().enumerate() {
            let mut cbc =
                AESCbc::<EmptyPadding>::new(AES::new(key.as_slice()).unwrap(), iv.clone()).unwrap();

            let mut data = pt.as_slice();
            let mut buf = vec![];
            let (in_len, out_len) = cbc
                .stream_encrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();
            assert_eq!(
                in_len,
                out_len,
                "case {i} stream encrypt failed, key bits len: {}",
                key.len() << 3
            );
            assert_eq!(
                buf,
                ct,
                "case {i} stream encrypt failed, key bits len: {}",
                key.len() << 3
            );

            let mut data = ct.as_slice();
            buf.clear();
            cbc.set_iv(iv.clone()).unwrap();
            let (in_len, out_len) = cbc
                .stream_decrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();
            assert_eq!(
                in_len,
                out_len,
                "case {i} stream encrypt failed, key bits len: {}",
                key.len() << 3
            );
            assert_eq!(
                buf,
                pt,
                "case {i} stream encrypt failed, key bits len: {}",
                key.len() << 3
            );

            let cbc: RefCell<_> = cbc.into();

            buf.clear();
            cbc.borrow_mut().set_iv(iv.clone()).unwrap();
            cbc.encrypt(pt.as_slice(), &mut buf).unwrap();
            assert_eq!(
                buf,
                ct,
                "case {i} stream encrypt failed, key bits len: {}",
                key.len() << 3
            );

            buf.clear();
            cbc.borrow_mut().set_iv(iv).unwrap();
            cbc.decrypt(ct.as_slice(), &mut buf).unwrap();
            assert_eq!(
                buf,
                pt,
                "case {i} stream encrypt failed, key bits len: {}",
                key.len() << 3
            );
        }
    }

    #[test]
    fn cbc_aes_default_padding() {
        for (i, (key, iv, pt, ct)) in cases().into_iter().enumerate() {
            let aes = AES::new(key.as_slice()).unwrap();
            let cbc: RefCell<_> = AESCbc::<DefaultPadding>::new(aes.clone(), iv.clone())
                .unwrap()
                .into();

            let padding = DefaultPadding::new(AES::BLOCK_SIZE);
            let mut cbc_out = vec![];
            cbc.encrypt(pt.as_slice(), &mut cbc_out).unwrap();
            assert_eq!(
                cbc_out.len(),
                ct.len() + padding.max_padding_blocks() * AES::BLOCK_SIZE,
                "case {i} failed, invalid result length"
            );
            assert_eq!(
                &cbc_out[..ct.len()],
                ct,
                "case {} failed, key bits len: {}",
                i,
                key.len() << 3
            );

            cbc.borrow_mut().set_iv(iv).unwrap();
            let mut buf = vec![];
            cbc.decrypt(cbc_out.as_slice(), &mut buf).unwrap();
            assert_eq!(
                buf,
                pt,
                "case {} failed, key bits len: {}",
                i,
                key.len() << 3
            );
        }
    }
}
