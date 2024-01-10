//! # The Cipher Block Chaining-Ciphertext Stealing (CBC-CS) <br>
//!
//! [NIST 800-38A-add, Three Variants of Ciphertext Stealing for CBC mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a-add.pdf)
//!
//! 该模式底层使用CBC算法, 相比较于CBC的优势是: 当数据不是分组大小整数倍时, 加解密无需指定额外的数据填充方式. <br>
//! 取名Ciphertext Stealing的原因是, 其会使用倒数第二个密文块进行填充对齐到分组大小的整数倍. <br>
//!
//! 限制: CBC-CS需要加解密数据的字节长度大于分组字节长度. <br>
//!
//! 记所使用的分组加密算法的分组字节大小为`b`, 明文为`P`, 密文为`C`. 有三种CS模式: <br>
//!
//! ## CBS-CS1 <br>
//!
//! - CBS-CS1-Encrypt:
//!   - `d = P.len() % b`, `n = (P.len() + b - 1) / b`.
//!     - 若`d != 0`则第`n`个分组补`b - d`个0.
//!   - CBC加密得到密文$(C_1, \cdots, C_n)$;
//!   - $C'_{n-1} = MSB_d(C_{n-1})$;
//!   - 密文: $C_1 || C_2 || \cdots || C'_{n-1} || C_n$.
//! - CBS-CS1-Decrypt:
//!   - `d = C.len() % b`, `n = (C.len() + b - 1) / b`.
//!     - 若`d != 0`说明$C_{n-1}$是不完整的, 记为$C'_{n-1}$
//!   - $Z' = MSB_d(CIPH^{-1}_K(C_n)), Z'' = LSB_{b-d}(CIPH^{-1}_K(C_n))$;
//!   - $C_{n-1}= C'_{n-1} || Z''$
//!   - CBC解密得到$(P_1, \cdots, P_{n-1})$;
//!   - $P'_n = C'_{n-1} \oplus Z'$
//!   - 明文: $P_1 || P_2 || \cdots || P_{n-1} || P'_n$
//!
//! 注: 原理是$C_n = CIPH_K(I_n), I_n = P' \oplus C_{n-1}' || C_{n-1}''$,
//! 即$C_{n-1}$的后半段可以通过$C_n$解密后的后半段得到;
//!
//! ## CBS-CS2 <br>
//!
//! - CBS-CS2-Encrypt
//!   - 使用CBS-CS1-Encrypt得到$C_1 || C_2 || \cdots || C'_{n-1} || C_n$;
//!   - 若`d=b`, 结果便是如上. 否则: $C_1 || C_2 || \cdots || C_n || C'_{n-1}$;
//! - CBS-CS2-Decrypt
//!   - 若`d != b`, 则调整顺序$C_1 || C_2 || \cdots || C'_n || C_{n-1}$;
//!   - 使用CBS-CS1-Decrypt解密
//!
//! ## CBS-CS3 <br>
//!
//! - CBS-CS3-Encrypt
//!   - 使用CBS-CS1-Encrypt得到$C_1 || C_2 || \cdots || C'_{n-1} || C_n$;
//!   - 输出$C_1 || C_2 || \cdots || C_n || C'_{n-1}$;
//! - CBS-CS3-Decrypt
//!   - 调整顺序$C_1 || C_2 || \cdots || C'_n || C_{n-1}$;
//!   - 使用CBS-CS1-Decrypt解密
//!
use crate::block_cipher::{AES, AES128, AES192, AES256};
use crate::cipher_mode::{EmptyPadding, CBC};
use crate::{
    BlockDecryptX, BlockEncryptX, CipherError, StreamCipherFinish, StreamDecrypt, StreamEncrypt,
};
use std::io::{Read, Write};
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CBCCsMode {
    CbcCs1,
    CbcCs2,
    CbcCs3,
}

/// 限制: CBC-CS需要加解密数据的字节长度大于分组字节长度.
pub struct CBCCs<E> {
    cbc: CBC<EmptyPadding, E>,
    in_buf: Vec<u8>,
    mode: CBCCsMode,
    is_encrypt: Option<bool>,
}

def_type_block_cipher!(
    CBCCs,
    <AESCbcCs, AES>,
    <AES128CbcCs, AES128>,
    <AES192CbcCs, AES192>,
    <AES256CbcCs, AES256>
);

impl<E: BlockEncryptX> CBCCs<E> {
    pub fn new(cipher: E, iv: Vec<u8>, mode: CBCCsMode) -> Result<Self, CipherError> {
        Ok(Self {
            cbc: CBC::new(cipher, iv)?,
            in_buf: vec![],
            mode,
            is_encrypt: None,
        })
    }

    pub fn set_iv(&mut self, iv: Vec<u8>) -> Result<(), CipherError> {
        self.cbc.set_iv(iv)
    }
}

impl<E> CBCCs<E> {
    fn clear_resource(&mut self) {
        self.is_encrypt = None;
        self.in_buf.clear();
        self.cbc.clear_resource();
    }

    fn set_working_flag(&mut self, is_encrypt: bool) -> Result<(), CipherError> {
        match self.is_encrypt {
            None => {
                self.in_buf.clear();
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

#[cfg(feature = "sec-zeroize")]
impl<E: Zeroize> Zeroize for CBCCs<E> {
    fn zeroize(&mut self) {
        self.cbc.zeroize();
    }
}

impl<E: BlockEncryptX> StreamEncrypt for CBCCs<E> {
    fn stream_encrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(true)?;

        let (mut buf, mut out_len, block_size) = (
            Vec::with_capacity(2048),
            0,
            self.cbc.get_cipher().block_size_x(),
        );
        buf.extend(self.in_buf.iter());
        self.in_buf.clear();
        let in_len = in_data.read_to_end(&mut buf).map_err(CipherError::from)?;

        let n = (buf.len() + block_size - 1) / block_size;
        let l = (n - 2) * block_size;
        // 保留最后两个分组
        if n > 2 {
            let mut data = &buf.as_slice()[..l];
            let s = self.cbc.stream_encrypt(&mut data, out_data)?;
            out_len += s.write_len();
        }
        self.in_buf.extend(buf.into_iter().skip(l));

        let s = StreamCipherFinish::new(self, (in_len, out_len), move |sf, outdata: &mut W| {
            let d = sf.in_buf.len() % block_size;
            if d != 0 {
                sf.in_buf.resize(sf.in_buf.len() + block_size - d, 0);
            }

            let mut last_txt = Vec::with_capacity(sf.in_buf.len());
            let mut data = sf.in_buf.as_slice();
            let _s = sf
                .cbc
                .stream_encrypt(&mut data, &mut last_txt)?
                .finish(&mut last_txt)?;

            if last_txt.len() != (block_size << 1) {
                return Err(CipherError::Other(format!(
                    "CBC-CS invalid last block length: {}",
                    last_txt.len()
                )));
            }

            let d = if d == 0 { block_size } else { d };
            if sf.mode == CBCCsMode::CbcCs1 || (sf.mode == CBCCsMode::CbcCs2 && d == block_size) {
                outdata
                    .write_all(&last_txt[0..d])
                    .map_err(CipherError::from)?;
                outdata
                    .write_all(&last_txt[block_size..])
                    .map_err(CipherError::from)?;
            } else {
                outdata
                    .write_all(&last_txt[block_size..])
                    .map_err(CipherError::from)?;
                outdata
                    .write_all(&last_txt[0..d])
                    .map_err(CipherError::from)?;
            }

            sf.clear_resource();
            Ok(block_size + d)
        });

        Ok(s)
    }
}

impl<E: BlockDecryptX> StreamDecrypt for CBCCs<E> {
    fn stream_decrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(false)?;

        let (mut buf, mut out_len, block_size) = (
            Vec::with_capacity(2048),
            0,
            self.cbc.get_cipher().block_size_x(),
        );
        buf.extend(self.in_buf.iter());
        self.in_buf.clear();
        let in_len = in_data.read_to_end(&mut buf).map_err(CipherError::from)?;

        let n = (buf.len() + block_size - 1) / block_size;
        let l = (n - 2) * block_size;
        // 保留最后两个分组
        if n > 2 {
            let mut data = &buf.as_slice()[..l];
            let s = self.cbc.stream_decrypt(&mut data, out_data)?;
            out_len += s.write_len();
        }
        self.in_buf.extend(buf.into_iter().skip(l));

        let s = StreamCipherFinish::new(self, (in_len, out_len), move |sf, outdata: &mut W| {
            if sf.in_buf.len() <= block_size || sf.in_buf.len() > (block_size << 1) {
                return Err(CipherError::Other(format!(
                    "CBC-CS invalid last block length: {}",
                    sf.in_buf.len()
                )));
            }

            let (d, mut c_n) = (sf.in_buf.len() - block_size, vec![]);
            if sf.mode == CBCCsMode::CbcCs1 || (sf.mode == CBCCsMode::CbcCs2 && d == block_size) {
                let data = &sf.in_buf.as_slice()[d..];
                sf.cbc.get_cipher().decrypt_block_x(data, &mut c_n)?;
                sf.in_buf.truncate(d);
            } else {
                let data = &sf.in_buf.as_slice()[..block_size];
                sf.cbc.get_cipher().decrypt_block_x(data, &mut c_n)?;
                sf.in_buf.rotate_right(d);
                sf.in_buf.truncate(d);
            };

            let (zp, zpp) = (&c_n[..d], &c_n[d..]);
            sf.in_buf.extend(zpp);
            let mut c_n_1 = sf.in_buf.as_slice();
            let (_, len1) = sf
                .cbc
                .stream_decrypt(&mut c_n_1, outdata)?
                .finish(outdata)?;
            sf.in_buf.iter_mut().zip(zp.iter()).for_each(|(a, &b)| {
                *a ^= b;
            });
            outdata
                .write_all(&sf.in_buf[0..d])
                .map_err(CipherError::from)?;

            sf.clear_resource();
            Ok(len1 + d)
        });

        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use crate::block_cipher::AES;
    use crate::cipher_mode::cbc::tests::cases;
    use crate::cipher_mode::{AESCbcCs, CBCCsMode};
    use crate::{Decrypt, Encrypt, StreamDecrypt, StreamEncrypt};
    use std::cell::RefCell;

    #[test]
    fn cbc_cs1() {
        for (i, (key, iv, pt, ct)) in cases().into_iter().enumerate() {
            let mut cbc = AESCbcCs::new(
                AES::new(key.as_slice()).unwrap(),
                iv.clone(),
                CBCCsMode::CbcCs1,
            )
            .unwrap();

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
}
