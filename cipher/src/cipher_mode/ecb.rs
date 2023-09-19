//! 笔记: `分组加密工作模式.md` <br>
//! <br>
//! ## The Electronic Codebook Mode(ECB)
//!
//! $$
//! C_j = Encrypt(P_j), j = 1...n
//!
//! P_j = Decrypt(C_j), j = 1...n
//! $$
//!
//! 给定的密钥, 每个明文块和密文块一一对应(如果不期待使用这一特性, 不应该使用ECB模式), 加解密都可并行. <br>
//! <br>
//!

use crate::block_cipher::{AES, AES128, AES192, AES256};
use crate::cipher_mode::BlockPadding;
use crate::stream_cipher::StreamCipherFinish;
use crate::{BlockCipher, BlockDecrypt, BlockEncrypt, CipherError, StreamDecrypt, StreamEncrypt};
use std::io::{Read, Write};
use utils::Block;
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

/// Electronic Codebook Mode <br>
///
/// `ECB<Padding, BlockCipher, BLOCK_SIZE>`
pub struct ECB<P, E, const BLOCK_SIZE: usize> {
    //缓存输入数据
    data: Block,
    //缓存输出数据
    out_buf: Vec<u8>,
    cipher: E,
    padding: P,
    is_encrypt: Option<bool>,
}

def_type_block_cipher!(
    ECB,
    [AESEcb, AES],
    [AES128Ecb, AES128],
    [AES192Ecb, AES192],
    [AES256Ecb, AES256]
);

impl_set_working_flag!(ECB);

impl<P, E, const N: usize> ECB<P, E, N> {
    fn clear_resource(&mut self) {
        self.is_encrypt = None;
        self.data.clear();
        self.out_buf.clear();
    }
}

impl<P, E, const BLOCK_SIZE: usize> ECB<P, E, BLOCK_SIZE>
where
    P: BlockPadding,
{
    pub fn new(cipher: E) -> Self {
        Self {
            data: Block::with_capacity(BLOCK_SIZE),
            out_buf: vec![],
            cipher,
            padding: P::new(BLOCK_SIZE),
            is_encrypt: None,
        }
    }

    pub fn set_padding(&mut self, padding: P) {
        self.padding = padding;
    }
}

#[cfg(feature = "sec-zeroize")]
impl<P, E, const N: usize> Zeroize for ECB<P, E, N>
where
    E: Zeroize,
{
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.data.zeroize();
    }
}

impl<P, E, const N: usize> StreamEncrypt for ECB<P, E, N>
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
        let mut buf = vec![];
        buf.resize(N << 1, 0);
        let (mut in_len, mut out_len) = (0, 0);

        loop {
            let s = in_data
                .read(&mut buf.as_mut_slice()[0..(N + N - self.data.len())])
                .map_err(CipherError::from)?;
            let mut data = &buf.as_slice()[0..s];

            if !self.data.is_empty() {
                let m = (N - self.data.len()).min(data.len());
                self.data.extend(&data[0..m]);
                data = &data[m..];
            }

            if let Some(arr) = self.data.as_arr() {
                out_data
                    .write_all(self.cipher.encrypt_block(arr).as_slice())
                    .map_err(CipherError::from)?;
                out_len += N;
                self.data.clear();
            }

            while data.len() >= N {
                let block = &data[..N];
                out_data
                    .write_all(
                        self.cipher
                            .encrypt_block(Block::as_arr_ref_uncheck(block))
                            .as_slice(),
                    )
                    .map_err(CipherError::from)?;
                out_len += N;
                data = &data[N..];
            }

            if !data.is_empty() {
                self.data.extend(data);
            }

            in_len += s;
            if s == 0 {
                break;
            }
        }

        let s = StreamCipherFinish::new(
            self,
            (in_len, out_len),
            |sf: &mut ECB<P, E, N>, outdata: &mut W| {
                sf.padding.padding(sf.data.as_mut());
                let mut data = sf.data.as_slice();

                let mut s = 0;
                while data.len() >= N {
                    let block = &data[0..N];
                    let c = sf.cipher.encrypt_block(Block::as_arr_ref_uncheck(block));
                    outdata.write_all(c.as_slice()).map_err(CipherError::from)?;
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
            },
        );

        Ok(s)
    }
}

impl<P, E, const N: usize> StreamDecrypt for ECB<P, E, N>
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
                let d = self.cipher.decrypt_block(arr);
                self.out_buf.extend(d);
                self.data.clear();
            }

            while data.len() >= N {
                let d = self
                    .cipher
                    .decrypt_block(Block::as_arr_ref_uncheck(&data[0..N]));
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

        let s =
            StreamCipherFinish::new(self, (in_len, out_len), |sf: &mut Self, outdata: &mut W| {
                let mut data = sf.data.as_slice();

                while data.len() >= N {
                    let d = sf
                        .cipher
                        .decrypt_block(Block::as_arr_ref_uncheck(&data[..N]));
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
    use crate::block_cipher::{BlockCipher, AES};
    use crate::cipher_mode::{AESEcb, BlockPadding, DefaultPadding, EmptyPadding};
    use crate::{Decrypt, Encrypt};
    use std::cell::RefCell;

    fn cases() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        [
            (
                // Appendix B.
                vec![
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ],
                vec![
                    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0,
                    0x37, 0x07, 0x34, 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                    0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                ],
                vec![
                    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19,
                    0x6a, 0x0b, 0x32, 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e,
                    0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
                ],
            ),
            (
                // Appendix C.1.  AES-128
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ],
                vec![
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                vec![
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ],
            ),
            (
                // Appendix C.2.  AES-192
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                ],
                vec![
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                vec![
                    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec,
                    0x0d, 0x71, 0x91,
                ],
            ),
            (
                // Appendix C.3.  AES-256
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                vec![
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                vec![
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b,
                    0x49, 0x60, 0x89,
                ],
            ),
        ]
        .to_vec()
    }

    #[test]
    fn ecb_aes_empty_padding() {
        for (i, (key, plaintext, ciphertext)) in cases().into_iter().enumerate() {
            let mut data = plaintext.as_slice();
            let cipher = AES::new(key.as_slice()).unwrap();

            // let mut ecb = ECB::<EmptyPadding, AES, { AES::BLOCK_SIZE }>::new(cipher);
            let mut ecb = AESEcb::<EmptyPadding>::new(cipher);

            let mut buf = Vec::with_capacity(ciphertext.len());
            let (in_len, out_len) = ecb
                .stream_encrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();

            assert_eq!(
                in_len,
                out_len,
                "case {} stream encrypt failed, key bits len: {}",
                i,
                key.len() << 3
            );
            assert_eq!(
                buf,
                ciphertext,
                "case {} stream encrypt failed, key bits len: {}",
                i,
                key.len() << 3
            );

            let mut data = ciphertext.as_slice();
            buf.clear();
            let (in_len, out_len) = ecb
                .stream_decrypt(&mut data, &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();

            assert_eq!(
                in_len,
                out_len,
                "case {} stream encrypt failed, key bits len: {}",
                i,
                key.len() << 3
            );
            assert_eq!(
                buf,
                plaintext,
                "case {} stream encrypt failed, key bits len: {}",
                i,
                key.len() << 3
            );

            buf.clear();
            let ecb: RefCell<_> = ecb.into();
            ecb.encrypt(plaintext.as_slice(), &mut buf).unwrap();
            assert_eq!(
                buf,
                ciphertext,
                "case {} encrypt failed with `EmptyPadding`, key bits len: {}",
                i,
                key.len() << 3
            );
            buf.clear();
            ecb.decrypt(ciphertext.as_slice(), &mut buf).unwrap();
            assert_eq!(
                buf,
                plaintext,
                "case {} decrypt failed with `EmptyPadding`, key bits len: {}",
                i,
                key.len() << 3
            )
        }
    }

    #[test]
    fn ecb_aes_default_padding() {
        for (i, (key, plaintext, ciphertext)) in cases().into_iter().enumerate() {
            let (aes, padding) = (
                AES::new(key.as_slice()).unwrap(),
                DefaultPadding::new(AES::BLOCK_SIZE),
            );
            let ecb = AESEcb::<DefaultPadding>::new(aes.clone());
            let ecb: RefCell<_> = ecb.into();
            let mut aes_data = plaintext.clone();
            padding.padding(&mut aes_data);
            let (mut aes_out, mut ecb_out) = (vec![], vec![]);
            for chunk in aes_data.chunks(AES::BLOCK_SIZE) {
                aes.encrypt(chunk, &mut aes_out).unwrap();
            }
            ecb.encrypt(plaintext.as_slice(), &mut ecb_out).unwrap();

            assert_eq!(
                &aes_out[0..ciphertext.len()],
                ciphertext,
                "case {} AES encrypt failed, key bits len: {}",
                i,
                key.len() << 3
            );
            assert_eq!(
                ecb_out,
                aes_out,
                "case {} failed, key bits len: {}",
                i,
                key.len() << 3
            );

            ecb_out.clear();
            ecb.decrypt(aes_out.as_slice(), &mut ecb_out).unwrap();
            assert_eq!(
                ecb_out,
                plaintext,
                "case {} failed, key bits len: {}",
                i,
                key.len() << 3
            );
        }
    }
}
