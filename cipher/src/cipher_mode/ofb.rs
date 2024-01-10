//! ## The Output Feedback Mode(OFB)
//!
//! 给定初始向量IV, **其需要是一个nonce值**. 即对于给定的密钥, 每次执行OFB模式时, $IV$都需要是独一无二的(unique), 且需要是保密的. <br>
//!
//! $$
//! I_1 = IV; I_j = O_{j-1}, j = 2...n; O_j = Encrypt(I_j), C_j = P_j \xor O_j, j = 1...n-1; C'_n = P'_n \xor MSB_u(O_n);
//!
//! I_1 = IV; I_j = O_{j-1}, j = 2...n; O_j = Encrypt(I_j), P_j = C_j \xor O_j, j = 1...n-1; P'_n = C'_n \xor MSB_u(O_n);
//! $$
//!
//! 从OFB的工作方式可以看出, 每次加解密都依赖于前一次的加解密, 因此加解密都是无法并行的. 另外, $IV$的保密性随机性需要保证,
//! 否则某个明文泄露则之后的密文都会计算出来, 从而之后的明文都会解密出来. <br>
//! <br>
//!

use crate::block_cipher::{AES, AES128, AES192, AES256};
use crate::{BlockEncryptX, CipherError, StreamCipherFinish, StreamDecrypt, StreamEncrypt};
use std::io::{Read, Write};
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

/// The Output Feedback Mode(OFB) <br>
///
/// 给定初始向量IV, **其需要是一个nonce值**. 即对于给定的密钥, 每次执行OFB模式时, $IV$都需要是独一无二的(unique), 且需要是保密的. <br>
pub struct OFB<E> {
    //缓存输入数据
    data: Vec<u8>,
    /// 初始化向量
    iv: Vec<u8>,
    cipher: E,
    is_encrypt: Option<bool>,
}

def_type_block_cipher!(
    OFB,
    <AESOfb, AES>,
    <AES128Ofb, AES128>,
    <AES192Ofb, AES192>,
    <AES256Ofb, AES256>
);

impl<E> OFB<E> {
    fn clear_resource(&mut self) {
        self.is_encrypt = None;
        self.data.clear();
        self.iv.clear();
    }

    fn check_iv(&self) -> Result<(), CipherError> {
        if self.iv.is_empty() {
            Err(CipherError::NotSetInitialVec)
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

impl<E: BlockEncryptX> OFB<E> {
    pub fn new(cipher: E, iv: Vec<u8>) -> Result<Self, CipherError> {
        if iv.len() != cipher.block_size_x() {
            return Err(CipherError::InvalidKeySize {
                real: iv.len(),
                target: Some(cipher.block_size_x()),
            });
        }

        Ok(Self {
            data: vec![],
            iv,
            cipher,
            is_encrypt: None,
        })
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

impl<E> OFB<E>
where
    E: BlockEncryptX,
{
    fn encrypt_inner(
        cipher: &E,
        data: &[u8],
        iv: &mut Vec<u8>,
        cdata: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        cdata.clear();
        cipher.encrypt_block_x(iv.as_slice(), cdata)?;
        iv.copy_from_slice(cdata);

        cdata
            .iter_mut()
            .zip(data.iter())
            .for_each(|(a, &b)| *a ^= b);

        Ok(())
    }
}

#[cfg(feature = "sec-zeroize")]
impl<E: Zeroize> Zeroize for OFB<E> {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.cipher.zeroize();
        self.iv.clear();
    }
}

impl<E> OFB<E>
where
    E: BlockEncryptX,
{
    fn stream_inner<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
        is_encrypt: bool,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(is_encrypt)?;
        self.check_iv()?;
        let (mut buf, mut out_len, n) = (Vec::with_capacity(2048), 0, self.cipher.block_size_x());

        buf.extend(self.data.iter());
        self.data.clear();
        let in_len = in_data.read_to_end(&mut buf).map_err(CipherError::from)?;

        let mut itr = buf.chunks_exact(n);
        for chunk in &mut itr {
            Self::encrypt_inner(&self.cipher, chunk, &mut self.iv, &mut self.data)?;
            out_data
                .write_all(self.data.as_slice())
                .map_err(CipherError::from)?;
            out_len += n;
        }
        self.data.clear();
        self.data.extend(itr.remainder());

        let s = StreamCipherFinish::new(self, (in_len, out_len), |sf, outdata: &mut W| {
            let mut s = 0;
            if !sf.data.is_empty() {
                let mut buf = vec![];
                Self::encrypt_inner(&sf.cipher, sf.data.as_slice(), &mut sf.iv, &mut buf)?;
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

impl<E> StreamEncrypt for OFB<E>
where
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

impl<E> StreamDecrypt for OFB<E>
where
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
    use crate::cipher_mode::AESOfb;
    use crate::{BlockCipher, Decrypt, Encrypt, StreamDecrypt, StreamEncrypt};
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
                "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e"
            ),
            (
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a"
            ),
            (
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484",
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
    fn ofb_aes() {
        for (i, (key, iv, pt, ct)) in cases().into_iter().enumerate() {
            let mut ofb = AESOfb::new(AES::new(key.as_slice()).unwrap(), iv.clone()).unwrap();

            let (mut data, mut buf) = (pt.as_slice(), vec![]);
            let (ilen, olen) = ofb
                .stream_encrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();

            assert_eq!(
                ilen, olen,
                "case {i} failed, stream encrypt input length not equal to output length"
            );
            assert_eq!(buf, ct, "case {i} stream encrypt failed");

            ofb.set_iv(iv.clone()).unwrap();
            let (mut data, mut buf) = (ct.as_slice(), vec![]);
            let (ilen, olen) = ofb
                .stream_decrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();

            assert_eq!(
                ilen, olen,
                "case {i} failed, stream encrypt input length not equal to output length"
            );
            assert_eq!(buf, pt, "case {i} stream encrypt failed");

            let ofb: RefCell<_> = ofb.into();
            buf.clear();
            ofb.borrow_mut().set_iv(iv.clone()).unwrap();
            ofb.encrypt(pt.as_slice(), &mut buf).unwrap();
            assert_eq!(buf, ct, "case {i} encrypt failed");

            buf.clear();
            ofb.borrow_mut().set_iv(iv).unwrap();
            ofb.decrypt(ct.as_slice(), &mut buf).unwrap();
            assert_eq!(buf, pt, "case {i} decrypt failed");
        }
    }
}
