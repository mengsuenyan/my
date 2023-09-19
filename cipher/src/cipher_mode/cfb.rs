//! ## The Cipher Feedback Mode(CFB)
//!
//! 记有初始向量IV(IV可以不保密, 但是**它必须是不可预测的(unpredictable)**.), b是分组加密函数的分组位大小, s是给定的整数参数满足$1 \le s \le b$. <br>
//!
//! $$
//! I_1 = IV; I_j = LSB_{b-s}(I_{j-1}) | C'_{j-1}, j = 2...n; O_j = Encrypt(I_j), j = 1...n; C'_j = P'_j \xor MSB_{s}(O_j), j = 1...n;
//!
//! I_1 = IV; I_j = LSB_{b-s}(I_{j-1}) | C'_{j-1}, j = 2...n; O_j = Encrypt(I_j), j = 1...n; P'_j = C'_j \xor MSB_{s}(O_j), j = 1...n;
//! $$
//!
//! 在CFB模式中, 当前加密的输入块数据是上一次的加密输出和上一次的加密输入的结合, 即当前加密输出反馈到输出结合得到下一个加密的输入. <br>
//! 每次加密依赖前一次的加密输出, 故Encrypt无法并行. Decrypt的输入是依赖前一次的输入, 当每次加密的输入$IV_j$都计算出来的前提下, Decrypt是可并行的. <br>
//! <br>
//!

use crate::block_cipher::{AES, AES128, AES192, AES256};
use crate::{
    BlockCipher, BlockEncrypt, BlockPadding, CipherError, StreamCipherFinish, StreamDecrypt,
    StreamEncrypt,
};
use std::collections::VecDeque;
use std::io::{Read, Write};
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

/// The Cipher Feedback Mode(CFB)
///
/// 给定初始向量IV, IV可以不保密, 但是**它必须是不可预测的(unpredictable)**. 因此, 使用过后再次进行加解密时需调用`self.set_iv`设置新的`IV`. <br>
pub struct CFB<P, E, const BLOCK_SIZE: usize> {
    //缓存输入数据
    data: Vec<u8>,
    //缓存输出数据
    out_buf: VecDeque<[u8; BLOCK_SIZE]>,
    /// 初始化向量
    iv: Option<[u8; BLOCK_SIZE]>,
    cipher: E,
    padding: P,
    is_encrypt: Option<bool>,
    // CFB中的s参数, 为方便处理这里是字节数
    s: usize,
}

impl_set_working_flag!(CFB);

def_type_block_cipher!(
    CFB,
    [AESCfb, AES],
    [AES128Cfb, AES128],
    [AES192Cfb, AES192],
    [AES256Cfb, AES256]
);

impl<P, E, const N: usize> CFB<P, E, N> {
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

impl<P, E, const N: usize> CFB<P, E, N>
where
    P: BlockPadding,
{
    /// `bytes`指定CFB的`s`参数, 单位: 字节.
    pub fn new(cipher: E, iv: [u8; N], bytes: usize) -> Result<Self, CipherError> {
        if bytes > N || bytes == 0 {
            return Err(CipherError::Other(format!(
                "Invalid CFB s parameter: {}, s should satisfies with `0 < s <= {}`",
                bytes, N
            )));
        }

        Ok(Self {
            data: Vec::with_capacity(bytes),
            out_buf: VecDeque::new(),
            iv: Some(iv),
            cipher,
            padding: P::new(bytes),
            is_encrypt: None,
            s: bytes,
        })
    }

    pub fn set_padding(&mut self, padding: P) {
        self.padding = padding;
    }

    pub fn set_iv(&mut self, iv: [u8; N]) {
        self.iv = Some(iv);
    }
}

impl<P, E, const N: usize> CFB<P, E, N>
where
    E: BlockEncrypt<N>,
    P: BlockPadding,
{
    // I_1 = IV; I_j = LSB_{b-s}(I_{j-1}) | C'_{j-1}, j = 2...n; O_j = Encrypt(I_j), j = 1...n; C'_j = P'_j \xor MSB_{s}(O_j), j = 1...n;
    // 调用者保证`data.len() == s`
    // 结果截取前`s`字节
    fn encrypt_inner(cipher: &E, iv: &mut [u8; N], data: &[u8]) -> [u8; N] {
        let s = data.len();
        let oj = cipher.encrypt_block(&*iv);

        let mut cj = [0u8; N];
        cj.iter_mut()
            .zip(data.iter().zip(oj.iter()))
            .for_each(|(a, (b, c))| {
                *a = b ^ c;
            });

        // ij
        iv.rotate_right(N - s);
        iv.iter_mut()
            .skip(N - s)
            .zip(cj.iter())
            .for_each(|(a, &b)| {
                *a = b;
            });

        cj
    }

    fn decrypt_inner(cipher: &E, iv: &mut [u8; N], data: &[u8]) -> [u8; N] {
        let s = data.len();
        let oj = cipher.encrypt_block(&*iv);

        let mut pj = [0u8; N];
        pj.iter_mut()
            .zip(data.iter().zip(oj.iter()))
            .for_each(|(a, (b, c))| {
                *a = b ^ c;
            });

        iv.rotate_right(N - s);
        iv.iter_mut()
            .skip(N - s)
            .zip(data.iter())
            .for_each(|(a, &b)| {
                *a = b;
            });

        pj
    }
}

#[cfg(feature = "sec-zeroize")]
impl<P, E, const N: usize> Zeroize for CFB<P, E, N>
where
    E: Zeroize,
{
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.data.zeroize();
        self.iv.zeroize();
    }
}

impl<P, E, const N: usize> StreamEncrypt for CFB<P, E, N>
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
        let (mut buf, n, mut out_len) = (Vec::with_capacity(2048), self.s, 0);

        buf.extend(self.data.iter());
        self.data.clear();
        let in_len = in_data.read_to_end(&mut buf).map_err(CipherError::from)?;
        let mut itr = buf.chunks_exact(n);
        for chunk in &mut itr {
            let d = Self::encrypt_inner(&self.cipher, self.iv.as_mut().unwrap(), chunk);
            out_data.write_all(&d[..n]).map_err(CipherError::from)?;
            out_len += n;
        }
        self.data.extend(itr.remainder());

        let s = StreamCipherFinish::new(self, (in_len, out_len), move |sf, outdata: &mut W| {
            sf.padding.padding(sf.data.as_mut());
            let mut itr = sf.data.chunks_exact(n);

            let mut out_len = 0;
            for data in &mut itr {
                let d = Self::encrypt_inner(&sf.cipher, sf.iv.as_mut().unwrap(), data);
                outdata.write_all(&d[..n]).map_err(CipherError::from)?;
                out_len += n;
            }

            let len = itr.remainder().len();
            sf.clear_resource();
            if len > 0 {
                Err(CipherError::InvalidBlockSize {
                    target: n,
                    real: len,
                })
            } else {
                Ok(out_len)
            }
        });

        Ok(s)
    }
}

impl<P, E, const N: usize> StreamDecrypt for CFB<P, E, N>
where
    E: BlockEncrypt<N>,
    P: BlockPadding,
{
    fn stream_decrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(false)?;
        self.check_iv()?;

        let n = self.s;
        let padding_blocks = self.padding.max_padding_blocks().max(1);
        let (tgt_len, mut out_len, mut buf) = (
            padding_blocks.max(32) + padding_blocks,
            0,
            Vec::with_capacity(2048),
        );

        buf.extend(self.data.iter());
        self.data.clear();
        let in_len = in_data.read_to_end(&mut buf).map_err(CipherError::from)?;
        let mut itr = buf.chunks_exact(n);
        for chunk in &mut itr {
            let d = Self::decrypt_inner(&self.cipher, self.iv.as_mut().unwrap(), chunk);
            self.out_buf.push_back(d);
            if self.out_buf.len() > tgt_len {
                while self.out_buf.len() > padding_blocks {
                    out_data
                        .write_all(&self.out_buf.pop_front().unwrap()[..n])
                        .map_err(CipherError::from)?;
                    out_len += n;
                }
            }
        }
        self.data.extend(itr.remainder());

        let s = StreamCipherFinish::new(self, (in_len, out_len), move |sf, outdata: &mut W| {
            let mut itr = sf.data.chunks_exact(n);
            for data in &mut itr {
                let d = Self::decrypt_inner(&sf.cipher, sf.iv.as_mut().unwrap(), data);
                sf.out_buf.push_back(d);
            }

            let len = itr.remainder().len();
            if len > 0 {
                sf.clear_resource();
                Err(CipherError::InvalidBlockSize {
                    target: n,
                    real: len,
                })
            } else {
                let mut buf = Vec::with_capacity(sf.out_buf.len() * n);
                sf.out_buf.iter().for_each(|x| {
                    buf.extend(&x[..n]);
                });
                sf.padding.unpadding(&mut buf)?;

                outdata
                    .write_all(buf.as_slice())
                    .map_err(CipherError::from)?;
                sf.clear_resource();
                Ok(buf.len())
            }
        });

        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use crate::block_cipher::AES;
    use crate::cipher_mode::{AESCfb, DefaultPadding, EmptyPadding};
    use crate::{BlockCipher, BlockPadding, Decrypt, Encrypt, StreamDecrypt, StreamEncrypt};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::cell::RefCell;

    fn cases() -> Vec<(usize, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let cases = [
            (
                1,
                "2b7e151628aed2a6abf7158809cf4f3c",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d",
                "3b79424c9c0dd436bace9e0ed4586a4f32b9"
            ),
            (
                1,
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d",
                "cda2521ef0a905ca44cd057cbf0d47a0678a"
            ),
            (
                1,
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d",
                "dc1f1a8520a64db55fcc8ac554844e889700"
            ),
            (
                16,
                "2b7e151628aed2a6abf7158809cf4f3c",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
            ),
            (
                16,
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff",
            ),
            (
                16,
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471",
            ),
        ];

        cases
            .into_iter()
            .map(|(s, key, iv, pt, ct)| {
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

                (s, key, iv, pt, ct)
            })
            .collect()
    }

    #[test]
    fn cfb_aes_empty_padding() {
        for (i, (s, key, iv, pt, ct)) in cases().into_iter().enumerate() {
            let iv: [u8; AES::BLOCK_SIZE] = iv.try_into().unwrap();
            let mut cfb =
                AESCfb::<EmptyPadding>::new(AES::new(key.as_slice()).unwrap(), iv, s).unwrap();

            let mut data = pt.as_slice();
            let mut buf = vec![];
            let (in_len, out_len) = cfb
                .stream_encrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();
            assert_eq!(
                in_len,
                out_len,
                "case {i} stream encrypt failed, key bits len: {}, s: {}",
                key.len() << 3,
                s
            );
            assert_eq!(
                buf,
                ct,
                "case {i} stream encrypt failed, key bits len: {}, s: {}",
                key.len() << 3,
                s
            );

            let mut data = ct.as_slice();
            buf.clear();
            cfb.set_iv(iv);
            let (in_len, out_len) = cfb
                .stream_decrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();
            assert_eq!(
                in_len,
                out_len,
                "case {i} stream encrypt failed, key bits len: {}, s: {}",
                key.len() << 3,
                s
            );
            assert_eq!(
                buf,
                pt,
                "case {i} stream encrypt failed, key bits len: {}, s: {}",
                key.len() << 3,
                s
            );

            let cfb: RefCell<_> = cfb.into();

            buf.clear();
            cfb.borrow_mut().set_iv(iv);
            cfb.encrypt(pt.as_slice(), &mut buf).unwrap();
            assert_eq!(
                buf,
                ct,
                "case {i} stream encrypt failed, key bits len: {}, s: {}",
                key.len() << 3,
                s
            );

            buf.clear();
            cfb.borrow_mut().set_iv(iv);
            cfb.decrypt(ct.as_slice(), &mut buf).unwrap();
            assert_eq!(
                buf,
                pt,
                "case {i} stream encrypt failed, key bits len: {}, s: {}",
                key.len() << 3,
                s
            );
        }
    }

    #[test]
    fn cfb_aes_default_padding() {
        for (i, (s, key, iv, pt, ct)) in cases().into_iter().enumerate() {
            let iv: [u8; AES::BLOCK_SIZE] = iv.try_into().unwrap();
            let aes = AES::new(key.as_slice()).unwrap();
            let cfb: RefCell<_> = AESCfb::<DefaultPadding>::new(aes.clone(), iv, s)
                .unwrap()
                .into();

            let padding = DefaultPadding::new(AES::BLOCK_SIZE);
            let mut cfb_out = vec![];
            cfb.encrypt(pt.as_slice(), &mut cfb_out).unwrap();
            assert_eq!(
                cfb_out.len(),
                ct.len() + padding.max_padding_blocks() * s,
                "case {i} failed, invalid result length"
            );
            assert_eq!(
                &cfb_out[..ct.len()],
                ct,
                "case {} failed, key bits len: {}",
                i,
                key.len() << 3
            );

            cfb.borrow_mut().set_iv(iv);
            let mut buf = vec![];
            cfb.decrypt(cfb_out.as_slice(), &mut buf).unwrap();
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
