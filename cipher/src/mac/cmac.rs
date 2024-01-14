//! Block Cipher-based Message Authentication Code (CMAC) <br>
//!
//! - [Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf) <br>
//!
//! - 流程:
//!   - subkey: 子密钥派生;
//!   - MAC生成;
//!   - MAC验证
//!

use crate::{BlockEncryptX, CipherError, MAC};
use std::io::Write;
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

pub struct CMAC<E> {
    k1: Vec<u8>,
    k2: Vec<u8>,
    buf: Vec<u8>,
    // C_i
    ci: Vec<u8>,
    // 下一个可以存放数据的索引
    buf_idx: usize,
    cipher: E,
    is_finalize: bool,
}

impl<E: BlockEncryptX> CMAC<E> {
    // https://op.dr.eck.cologne/en/theme/crypto_karisik/eax_cmac_problem.shtml
    // Block size 	Calculation 	Polynomal (hex) 	Polynomal (bit)
    // 32 	2^7+2^3+2^2+1 	0x8D 	10001101
    // 48 	2^5+2^3+2^2+1 	0x2D 	101101
    // 64 	2^4+2^3+2^1+1 	0x1B 	11011
    // 96 	2^10+2^9+2^6+1 	0x641 	11001000001
    // 128 	2^7+2^2+2^1+1 	0x87 	10000111
    // 160 	2^5+2^3+2^2+1 	0x2D 	101101
    // 192 	2^7+2^2+2^1+1 	0x87 	10000111
    // 224 	2^9+2^8+2^3+1 	0x309 	1100001001
    // 256 	2^10+2^5+2^2+1 	0x425 	10000100101
    // 320 	2^4+2^3+2^1+1 	0x1B 	11011
    // 384 	2^12+2^3+2^2+1 	0x100D 	1000000001101
    // 448 	2^11+2^6+2^4+1 	0x851 	100001010001
    // 512 	2^8+2^5+2^2+1 	0x125 	100100101
    // 768 	2^19+2^17+2^4+1 	0xA0011 	10100000000000010001
    // 1024 	2^19+2^6+2^1+1 	0x80043 	10000000000001000011
    // 2048 	2^19+2^14+2^13+1 	0x86001 	10000110000000000001
    const fn rb(n: usize) -> Option<[u8; 4]> {
        match n {
            4 => Some(0x8du32.to_be_bytes()),
            6 => Some(0x2du32.to_be_bytes()),
            8 => Some(0x1bu32.to_be_bytes()),
            12 => Some(0x641u32.to_be_bytes()),
            16 => Some(0x87u32.to_be_bytes()),
            20 => Some(0x2du32.to_be_bytes()),
            24 => Some(0x87u32.to_be_bytes()),
            28 => Some(0x309u32.to_be_bytes()),
            32 => Some(0x425u32.to_be_bytes()),
            40 => Some(0x1bu32.to_be_bytes()),
            48 => Some(0x100du32.to_be_bytes()),
            56 => Some(0x851u32.to_be_bytes()),
            64 => Some(0x125u32.to_be_bytes()),
            96 => Some(0xa0011u32.to_be_bytes()),
            128 => Some(0x80043u32.to_be_bytes()),
            256 => Some(0x86001u32.to_be_bytes()),
            _ => None,
        }
    }

    fn shl_arr(mut arr: Vec<u8>, bits: usize) -> Vec<u8> {
        let mut lsb = 0;
        let r = 8 - bits;
        arr.iter_mut().rev().for_each(|x| {
            let tmp = lsb;
            lsb = *x >> r;
            *x <<= bits;
            *x |= tmp;
        });
        arr
    }
}

impl<E> CMAC<E>
where
    E: BlockEncryptX,
{
    pub fn new(cipher: E) -> Result<Self, CipherError> {
        let (k1, k2) = Self::subkey(&cipher)?;

        let n = cipher.block_size_x();
        Ok(Self {
            k1,
            k2,
            buf: vec![0u8; n],
            ci: vec![0u8; n],
            buf_idx: 0,
            cipher,
            is_finalize: false,
        })
    }

    // (k1, k2)
    fn subkey(cipher: &E) -> Result<(Vec<u8>, Vec<u8>), CipherError> {
        let n = cipher.block_size_x();
        let rb = Self::rb(n).ok_or(CipherError::Other(format!(
            "CMAC Rb parameter not support {n} block size"
        )))?;

        let (mut l, zero) = (Vec::with_capacity(n), vec![0u8; n]);
        cipher.encrypt_block_x(zero.as_slice(), &mut l)?;

        let k1 = if (l[0] & 0x80) == 0 {
            Self::shl_arr(l, 1)
        } else {
            let mut l = Self::shl_arr(l, 1);
            l.iter_mut()
                .rev()
                .zip(rb.into_iter().rev())
                .for_each(|(a, b)| {
                    *a ^= b;
                });
            l
        };

        let k2 = if (k1[0] & 0x80) == 0 {
            Self::shl_arr(k1.clone(), 1)
        } else {
            let mut k1 = Self::shl_arr(k1.clone(), 1);
            k1.iter_mut()
                .rev()
                .zip(rb.into_iter().rev())
                .for_each(|(a, b)| {
                    *a ^= b;
                });
            k1
        };

        Ok((k1, k2))
    }
}

impl<E: Clone> Clone for CMAC<E> {
    fn clone(&self) -> Self {
        Self {
            buf_idx: self.buf_idx,
            buf: self.buf.clone(),
            cipher: self.cipher.clone(),
            ci: self.ci.clone(),
            k1: self.k1.clone(),
            k2: self.k2.clone(),
            is_finalize: self.is_finalize,
        }
    }
}

#[cfg(feature = "sec-zeroize")]
impl<E: Zeroize> Zeroize for CMAC<E> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.ci.zeroize();
        self.k1.zeroize();
        self.k2.zeroize();
        self.buf.zeroize();
    }
}

impl<E> Write for CMAC<E>
where
    E: BlockEncryptX,
{
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn write(&mut self, mut data: &[u8]) -> std::io::Result<usize> {
        if self.is_finalize {
            self.reset();
        }

        let (data_len, n) = (data.len(), self.block_size_x());
        if self.buf_idx != n {
            let l = (n - self.buf_idx).min(data.len());
            let bound = self.buf_idx + l;
            self.buf[self.buf_idx..bound].copy_from_slice(&data[..l]);
            self.buf_idx = bound;
            data = &data[l..];
        }

        let mut buf_cipher = Vec::with_capacity(n);
        if self.buf_idx + data.len() > n {
            // C_i = CIPH_k(C_{i-1} ^ M)
            self.buf.iter_mut().zip(self.ci.iter()).for_each(|(a, &b)| {
                *a ^= b;
            });
            self.ci.clear();
            self.cipher
                .encrypt_block_x(&self.buf, &mut self.ci)
                .map_err(std::io::Error::other)?;
            self.buf_idx = 0;

            while data.len() > n {
                self.ci
                    .iter_mut()
                    .zip(data.iter().take(n))
                    .for_each(|(a, &b)| {
                        *a ^= b;
                    });
                buf_cipher.clear();
                self.cipher
                    .encrypt_block_x(&self.ci, &mut buf_cipher)
                    .map_err(std::io::Error::other)?;
                self.ci.clear();
                self.ci.append(&mut buf_cipher);
                data = &data[n..];
            }
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_idx = data.len();
        }

        Ok(data_len)
    }
}

impl<E> MAC for CMAC<E>
where
    E: BlockEncryptX,
{
    fn block_size_x(&self) -> usize {
        self.cipher.block_size_x()
    }
    fn digest_size_x(&self) -> usize {
        self.block_size_x()
    }
    fn mac(&mut self) -> Vec<u8> {
        if self.is_finalize {
            return self.ci.to_vec();
        }

        let n = self.block_size_x();
        if self.buf_idx == n {
            self.ci
                .iter_mut()
                .zip(self.buf.iter().zip(self.k1.iter()))
                .for_each(|(a, (&b, &c))| {
                    *a ^= b ^ c;
                });
        } else {
            self.buf[self.buf_idx..].fill(0);
            self.buf[self.buf_idx] = 0x80;
            self.ci
                .iter_mut()
                .zip(self.buf.iter().zip(self.k2.iter()))
                .for_each(|(a, (&b, &c))| {
                    *a ^= b ^ c;
                })
        }

        let mut mac = Vec::with_capacity(self.digest_size_x());
        self.cipher.encrypt_block_x(&self.ci, &mut mac).unwrap();
        self.ci.copy_from_slice(&mac);
        self.is_finalize = true;
        mac
    }

    fn reset(&mut self) {
        self.ci.clear();
        self.ci.resize(self.cipher.block_size_x(), 0);
        self.buf_idx = 0;
        self.is_finalize = false;
    }
}

#[cfg(test)]
mod tests {
    use crate::block_cipher::AES;
    use crate::mac::CMAC;
    use crate::MAC;
    use std::io::Write;

    #[test]
    fn cmac_aes() {
        let cases = [
            (
                vec![0x2B7E1516u32, 0x28AED2A6, 0xABF71588, 0x09CF4F3C],
                vec![
                    (
                        vec![],
                        vec![0xBB1D6929u32, 0xE9593728, 0x7FA37D12, 0x9B756746],
                    ),
                    (
                        vec![0x6BC1BEE2u32, 0x2E409F96, 0xE93D7E11, 0x7393172A],
                        vec![0x070A16B4u32, 0x6B4D4144, 0xF79BDD9D, 0xD04A287C],
                    ),
                    (
                        vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57],
                        vec![0x7D85449E, 0xA6EA19C8, 0x23A7BF78, 0x837DFADE],
                    ),
                    (
                        vec![
                            0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C,
                            0x9EB76FAC, 0x45AF8E51, 0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF,
                            0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710,
                        ],
                        vec![0x51F0BEBF, 0x7E3B9D92, 0xFC497417, 0x79363CFE],
                    ),
                ],
            ),
            (
                vec![
                    0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5, 0x62F8EAD2, 0x522C6B7B,
                ],
                vec![
                    (vec![], vec![0xD17DDF46, 0xADAACDE5, 0x31CAC483, 0xDE7A9367]),
                    (
                        vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A],
                        vec![0x9E99A7BF, 0x31E71090, 0x0662F65E, 0x617C5184],
                    ),
                    (
                        vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57],
                        vec![0x3D75C194, 0xED960704, 0x44A9FA7E, 0xC740ECF8],
                    ),
                    (
                        vec![
                            0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C,
                            0x9EB76FAC, 0x45AF8E51, 0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF,
                            0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710,
                        ],
                        vec![0xA1D5DF0E, 0xED790F79, 0x4D775896, 0x59F39A11],
                    ),
                ],
            ),
            (
                vec![
                    0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781, 0x1F352C07, 0x3B6108D7,
                    0x2D9810A3, 0x0914DFF4,
                ],
                vec![
                    (vec![], vec![0x028962F6, 0x1B7BF89E, 0xFC6B551F, 0x4667D983]),
                    (
                        vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A],
                        vec![0x28A7023F, 0x452E8F82, 0xBD4BF28D, 0x8C37C35C],
                    ),
                    (
                        vec![0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57],
                        vec![0x156727DC, 0x0878944A, 0x023C1FE0, 0x3BAD6D93],
                    ),
                    (
                        vec![
                            0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, 0xAE2D8A57, 0x1E03AC9C,
                            0x9EB76FAC, 0x45AF8E51, 0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF,
                            0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710,
                        ],
                        vec![0xE1992190, 0x549F6ED5, 0x696A2C05, 0x6C315410],
                    ),
                ],
            ),
        ]
        .into_iter()
        .map(|(key, case)| {
            let key = key
                .into_iter()
                .map(|x| x.to_be_bytes())
                .flatten()
                .collect::<Vec<_>>();
            let case = case
                .into_iter()
                .map(|(msg, mac)| {
                    let msg = msg
                        .into_iter()
                        .map(|m| m.to_be_bytes())
                        .flatten()
                        .collect::<Vec<_>>();
                    let mac = mac
                        .into_iter()
                        .map(|m| m.to_be_bytes())
                        .flatten()
                        .collect::<Vec<_>>();
                    (msg, mac)
                })
                .collect::<Vec<_>>();

            (key, case)
        })
        .collect::<Vec<_>>();

        for (i, (key, case)) in cases.into_iter().enumerate() {
            let aes = AES::new(key.as_slice()).unwrap();
            let mut cmac = CMAC::new(aes).unwrap();
            for (j, (msg, mac)) in case.into_iter().enumerate() {
                cmac.write_all(msg.as_slice()).unwrap();
                let tgt = cmac.mac();
                assert_eq!(tgt, mac, "case {i}-{j} failed");
                cmac.reset();
            }
        }
    }
}
