//! ## The Counter Mode(CTR)
//!
//! 给定计数器, 其生成的计数值$T_i$每个都需要是相异的, 且需要是保密的. <br>
//!
//! $$
//! O_j = Encrypt(T_j), j = 1...n; C_j = P_j \xor O_j, j = 1...n-1; C'_n = P'_n \xor MSB_u(O_n);
//!
//! O_j = Encrypt(T_j), j = 1...n; P_j = C_j \xor O_j, j = 1...n-1; P'_n = C'_n \xor MSB_u(O_n);
//! $$
//!
//! 在CTR工作模式中, 如果每个$T_i$能提前计算出来, 那么加解密可以并行.
//!

use crate::block_cipher::{AES, AES128, AES192, AES256};
use crate::cipher_mode::Counter;
use crate::{BlockEncryptX, CipherError, StreamCipherFinish, StreamDecrypt, StreamEncrypt};
use std::io::{Read, Write};
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

/// The Counter Mode(CTR) <br>
///
/// 给定计数器`C`, 其生成的计数值$T_i$每个都需要是相异的, 且需要是保密的. <br>
pub struct CTR<C, E> {
    //缓存输入数据
    data: Vec<u8>,
    counter: Option<C>,
    cipher: E,
    is_encrypt: Option<bool>,
}

def_type_block_cipher!(
    CTR,
    [AESCtr, AES],
    [AES128Ctr, AES128],
    [AES192Ctr, AES192],
    [AES256Ctr, AES256]
);

impl<C, E> CTR<C, E> {
    fn clear_resource(&mut self) {
        self.is_encrypt = None;
        self.data.clear();
        self.counter = None;
    }

    fn check_counter(&self) -> Result<(), CipherError> {
        if self.counter.is_none() {
            Err(CipherError::NotSetCounter)
        } else {
            Ok(())
        }
    }

    fn set_working_flag(&mut self, is_encrypt: bool) -> Result<(), CipherError> {
        match self.is_encrypt {
            None => {
                self.data.clear();
                self.is_encrypt = Some(is_encrypt);
                Ok(())
            }
            Some(b) => {
                if b != is_encrypt {
                    Err(CipherError::BeWorking(b))
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl<C: Counter, E: BlockEncryptX> CTR<C, E> {
    pub fn new(cipher: E, counter: C) -> Result<Self, CipherError> {
        if counter.iv_bytes() < cipher.block_size_x() {
            return Err(CipherError::InvalidCounter {
                len: counter.iv_bytes(),
                is_iv: true,
            });
        }

        Ok(Self {
            data: Vec::with_capacity(cipher.block_size_x()),
            counter: Some(counter),
            cipher,
            is_encrypt: None,
        })
    }

    pub fn set_counter(&mut self, counter: C) -> Result<(), CipherError> {
        if counter.iv_bytes() < self.cipher.block_size_x() {
            Err(CipherError::InvalidCounter {
                len: counter.iv_bytes(),
                is_iv: true,
            })
        } else {
            self.counter = Some(counter);
            Ok(())
        }
    }
}

#[cfg(feature = "sec-zeroize")]
impl<C, E> Zeroize for CTR<C, E>
where
    E: Zeroize,
{
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.cipher.zeroize()
    }
}

impl<C, E> CTR<C, E>
where
    C: Counter,
    E: BlockEncryptX,
{
    // 调用者负责输出截断为`data.len()`
    fn encrypt_inner(
        sf: &E,
        counter: &mut C,
        data: &[u8],
        cdata: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        let Some(cnt) = counter.count() else {
            return Err(CipherError::InvalidCounter {
                len: 0,
                is_iv: false,
            });
        };

        if cnt.len() != sf.block_size_x() {
            return Err(CipherError::InvalidCounter {
                len: cnt.len(),
                is_iv: false,
            });
        }

        cdata.clear();
        sf.encrypt_block_x(cnt.as_slice(), cdata)?;
        cdata
            .iter_mut()
            .zip(data.iter())
            .for_each(|(a, &b)| *a ^= b);
        Ok(())
    }
}

impl<C, E> CTR<C, E>
where
    C: Counter,
    E: BlockEncryptX,
{
    fn stream_inner<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
        is_encrypt: bool,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(is_encrypt)?;
        self.check_counter()?;
        let (mut buf, mut out_len, n) = (Vec::with_capacity(2048), 0, self.cipher.block_size_x());

        buf.extend(self.data.iter());
        self.data.clear();
        let in_len = in_data.read_to_end(&mut buf).map_err(CipherError::from)?;

        let mut itr = buf.chunks_exact(n);
        for chunk in &mut itr {
            Self::encrypt_inner(
                &self.cipher,
                self.counter.as_mut().unwrap(),
                chunk,
                &mut self.data,
            )?;
            out_data
                .write_all(self.data.as_slice())
                .map_err(CipherError::from)?;
            out_len += n;
        }
        self.data.clear();
        self.data.extend(itr.remainder());

        let s = StreamCipherFinish::new(self, (in_len, out_len), move |sf, outdata: &mut W| {
            let mut s = 0;
            if !sf.data.is_empty() {
                let mut buf = vec![];
                Self::encrypt_inner(
                    &sf.cipher,
                    sf.counter.as_mut().unwrap(),
                    sf.data.as_slice(),
                    &mut buf,
                )?;
                outdata
                    .write_all(&buf[..sf.data.len()])
                    .map_err(CipherError::from)?;
                s += sf.data.len();
            }

            sf.clear_resource();
            Ok(s)
        });

        Ok(s)
    }
}

impl<C, E> StreamEncrypt for CTR<C, E>
where
    C: Counter,
    E: BlockEncryptX,
{
    fn stream_encrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.stream_inner(in_data, out_data, true)
    }
}

impl<C, E> StreamDecrypt for CTR<C, E>
where
    C: Counter,
    E: BlockEncryptX,
{
    fn stream_decrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.stream_inner(in_data, out_data, false)
    }
}

#[cfg(test)]
mod tests {
    use crate::block_cipher::AES;
    use crate::cipher_mode::{AESCtr, DefaultCounter};
    use crate::{Decrypt, Encrypt, StreamDecrypt, StreamEncrypt};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::cell::RefCell;
    use std::ops::Range;

    #[test]
    fn ctr_aes_default_counter() {
        let cases = [
            (
                "2b7e151628aed2a6abf7158809cf4f3c",
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
            ),
            (
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050"
            ),
            (
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
            ),
        ].into_iter().map(|(key, iv, pt, ct)| {
            (
                BigUint::from_str_radix(key, 16).unwrap().to_bytes_be(),
                BigUint::from_str_radix(iv, 16).unwrap().to_bytes_be(),
                BigUint::from_str_radix(pt, 16).unwrap().to_bytes_be(),
                BigUint::from_str_radix(ct, 16).unwrap().to_bytes_be(),
                )
        }).collect::<Vec<_>>();

        for (i, (key, iv, pt, ct)) in cases.into_iter().enumerate() {
            let cnt = DefaultCounter::new(iv, Range { start: 0, end: 128 }).unwrap();
            let aes = AES::new(key.as_slice()).unwrap();
            let mut ctr = AESCtr::<DefaultCounter>::new(aes, cnt.clone()).unwrap();

            let mut data = pt.as_slice();
            let mut buf = vec![];
            let (il, ol) = ctr
                .stream_encrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();
            assert_eq!(il, ol, "case {i} stream encrypt failed");
            assert_eq!(buf, ct, "case {i} stream encrypt failed");

            let mut data = ct.as_slice();
            buf.clear();
            ctr.set_counter(cnt.clone()).unwrap();
            let (il, ol) = ctr
                .stream_decrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();
            assert_eq!(il, ol, "case {i} stream encrypt failed");
            assert_eq!(buf, pt, "case {i} stream encrypt failed");

            let ctr: RefCell<_> = ctr.into();
            buf.clear();
            ctr.borrow_mut().set_counter(cnt.clone()).unwrap();
            ctr.encrypt(pt.as_slice(), &mut buf).unwrap();
            assert_eq!(buf, ct, "case {i} encrypt failed");
            buf.clear();
            ctr.borrow_mut().set_counter(cnt.clone()).unwrap();
            ctr.decrypt(ct.as_slice(), &mut buf).unwrap();
            assert_eq!(buf, pt, "case {i} decrypt failed");
        }
    }
}
