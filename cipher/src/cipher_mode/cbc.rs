use crate::block_cipher::{AES, AES128, AES192, AES256};
use crate::cipher_mode::BlockPadding;
use crate::{
    BlockCipher, BlockDecrypt, BlockEncrypt, CipherError, StreamCipherFinish, StreamDecrypt,
    StreamEncrypt,
};
use std::io::{Read, Write};
use utils::Block;
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

/// Cipher Block Chaining Mode(CBC) <br>
///
/// 给定初始向量IV, IV可以不保密, 但是**它必须是不可预测的(unpredictable)**. 因此, 使用过后再次进行加解密时需调用`self.set_iv`设置新的`IV`. <br>
pub struct CBC<P, E, const BLOCK_SIZE: usize> {
    //缓存输入数据
    data: Block,
    //缓存输出数据
    out_buf: Vec<u8>,
    /// 初始化向量
    iv: Option<[u8; BLOCK_SIZE]>,
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

impl<P, E, const N: usize> CBC<P, E, N> {
    fn clear_resource(&mut self) {
        self.is_encrypt = None;
        self.data.clear();
        self.out_buf.clear();
        self.iv = None;
    }

    fn check_iv(&self) -> Result<(), CipherError> {
        if self.iv.is_none() {
            Err(CipherError::NotSetInitialVec)
        } else {
            Ok(())
        }
    }
}

impl<P, E, const N: usize> CBC<P, E, N>
where
    P: BlockPadding,
{
    pub fn new(cipher: E, iv: [u8; N]) -> Self {
        Self {
            data: Block::with_capacity(N),
            out_buf: vec![],
            iv: Some(iv),
            cipher,
            padding: P::new(N),
            is_encrypt: None,
        }
    }

    pub fn set_padding(&mut self, padding: P) {
        self.padding = padding;
    }

    pub fn set_iv(&mut self, iv: [u8; N]) {
        self.iv = Some(iv);
    }
}

impl<P, E, const N: usize> CBC<P, E, N>
where
    E: BlockEncrypt<N>,
    P: BlockPadding,
{
    fn encrypt_inner(cipher: &E, iv: &mut [u8; N], block: &[u8; N]) -> [u8; N] {
        iv.iter_mut().zip(block.iter()).for_each(|(a, b)| *a ^= b);
        let d = cipher.encrypt_block(&*iv);
        iv.copy_from_slice(d.as_slice());
        d
    }
}

impl<P, E, const N: usize> CBC<P, E, N>
where
    E: BlockDecrypt<N>,
    P: BlockPadding,
{
    fn decrypt_inner(cipher: &E, iv: &mut [u8; N], block: &[u8; N]) -> [u8; N] {
        let mut d = cipher.decrypt_block(block);
        d.iter_mut().zip(iv.iter()).for_each(|(a, b)| {
            *a ^= b;
        });
        iv.copy_from_slice(block.as_slice());
        d
    }
}

#[cfg(feature = "sec-zeroize")]
impl<P, E, const N: usize> Zeroize for CBC<P, E, N>
where
    E: Zeroize,
{
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.data.zeroize();
        self.iv.zeroize();
    }
}

impl<P, E, const N: usize> StreamEncrypt for CBC<P, E, N>
where
    E: BlockEncrypt<N>,
    P: BlockPadding,
{
    fn stream_encrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(true)?;
        self.check_iv()?;
        let (mut in_len, mut out_len) = (0, 0);
        let mut buf = vec![];
        buf.resize(N << 1, 0);

        loop {
            let s = in_data
                .read(&mut buf.as_mut_slice()[0..(N + N - self.data.len())])
                .map_err(CipherError::from)?;
            let mut data = &buf.as_slice()[0..s];
            in_len += s;

            if !self.data.is_empty() {
                let m = (N - self.data.len()).min(data.len());
                self.data.extend(&data[0..m]);
                data = &data[m..];
            }

            if let Some(arr) = self.data.as_arr::<N>() {
                let d = Self::encrypt_inner(&self.cipher, self.iv.as_mut().unwrap(), arr);
                out_data
                    .write_all(d.as_slice())
                    .map_err(CipherError::from)?;
                out_len += N;
                self.data.clear();
            }

            while data.len() >= N {
                let block = Block::as_arr_ref_uncheck(&data[0..N]);
                let d = Self::encrypt_inner(&self.cipher, self.iv.as_mut().unwrap(), block);
                out_data
                    .write_all(d.as_slice())
                    .map_err(CipherError::from)?;
                out_len += N;
                data = &data[N..];
            }

            if !data.is_empty() {
                self.data.extend(data);
            }

            if s == 0 {
                break;
            }
        }

        let s = StreamCipherFinish::new(self, (in_len, out_len), |sf, outdata: &mut W| {
            sf.padding.padding(sf.data.as_mut());
            let mut data = sf.data.as_slice();

            let mut s = 0;
            while data.len() >= N {
                let block = Block::as_arr_ref_uncheck(&data[0..N]);
                let d = Self::encrypt_inner(&sf.cipher, sf.iv.as_mut().unwrap(), block);
                outdata.write_all(d.as_slice()).map_err(CipherError::from)?;
                s += N;
                data = &data[N..];
            }

            let len = data.len();
            sf.clear_resource();
            if len > 0 {
                Err(CipherError::InvalidBlockSize {
                    target: N,
                    real: len,
                })
            } else {
                Ok(s)
            }
        });

        Ok(s)
    }
}

impl<P, E, const N: usize> StreamDecrypt for CBC<P, E, N>
where
    E: BlockDecrypt<N>,
    P: BlockPadding,
{
    fn stream_decrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(false)?;
        self.check_iv()?;
        let (mut in_len, mut out_len) = (0, 0);
        let padding_len = self.padding.max_padding_blocks().max(1) * N;
        let tgt_len = padding_len * 32;
        let mut buf = vec![];
        buf.resize(N << 1, 0);

        loop {
            let s = in_data
                .read(&mut buf.as_mut_slice()[0..(N + N - self.data.len())])
                .map_err(CipherError::from)?;
            let mut data = &buf[0..s];
            in_len += s;

            if !self.data.is_empty() {
                let l = (N - self.data.len()).min(data.len());
                self.data.extend(&data[0..l]);
                data = &data[l..];
            }

            if let Some(arr) = self.data.as_arr() {
                let d = Self::decrypt_inner(&self.cipher, self.iv.as_mut().unwrap(), arr);
                self.out_buf.extend(d);
                self.data.clear();
            }

            while data.len() >= N {
                let arr = Block::as_arr_ref_uncheck(&data[0..N]);
                let d = Self::decrypt_inner(&self.cipher, self.iv.as_mut().unwrap(), arr);
                self.out_buf.extend(d);
                data = &data[N..];
            }

            if !data.is_empty() {
                self.data.extend(data);
            }

            if s == 0 {
                break;
            }

            let l = self.out_buf.len();
            if l >= tgt_len {
                out_data
                    .write_all(&self.out_buf.as_slice()[0..(l - padding_len)])
                    .map_err(CipherError::from)?;
                out_len += l - padding_len;
                for i in 0..padding_len {
                    self.out_buf.swap(i, l - padding_len + i);
                }
                self.out_buf.truncate(padding_len);
            }
        }

        let s = StreamCipherFinish::new(self, (in_len, out_len), |sf, outdata: &mut W| {
            let mut data = sf.data.as_slice();

            while data.len() >= N {
                let arr = Block::as_arr_ref_uncheck(&data[..N]);
                let d = Self::decrypt_inner(&sf.cipher, sf.iv.as_mut().unwrap(), arr);
                sf.out_buf.extend(d);
                data = &data[N..];
            }

            let len = data.len();
            if len > 0 {
                sf.clear_resource();
                Err(CipherError::InvalidBlockSize {
                    target: N,
                    real: len,
                })
            } else {
                sf.padding.unpadding(&mut sf.out_buf)?;

                let s = sf.out_buf.len();
                outdata
                    .write_all(sf.out_buf.as_slice())
                    .map_err(CipherError::from)?;
                sf.clear_resource();
                Ok(s)
            }
        });

        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::{StreamDecrypt, StreamEncrypt};
    use crate::block_cipher::AES;
    use crate::cipher_mode::{AESCbc, DefaultPadding, EmptyPadding};
    use crate::{BlockCipher, BlockPadding, Decrypt, Encrypt};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::cell::RefCell;

    /// (key, iv, plaintext, ciphertext)
    fn cases() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
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
            let iv: [u8; AES::BLOCK_SIZE] = iv.try_into().unwrap();
            let mut cbc = AESCbc::<EmptyPadding>::new(AES::new(key.as_slice()).unwrap(), iv);

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
            cbc.set_iv(iv);
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
            cbc.borrow_mut().set_iv(iv);
            cbc.encrypt(pt.as_slice(), &mut buf).unwrap();
            assert_eq!(
                buf,
                ct,
                "case {i} stream encrypt failed, key bits len: {}",
                key.len() << 3
            );

            buf.clear();
            cbc.borrow_mut().set_iv(iv);
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
            let iv: [u8; AES::BLOCK_SIZE] = iv.try_into().unwrap();
            let aes = AES::new(key.as_slice()).unwrap();
            let cbc: RefCell<_> = AESCbc::<DefaultPadding>::new(aes.clone(), iv).into();

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

            cbc.borrow_mut().set_iv(iv);
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
