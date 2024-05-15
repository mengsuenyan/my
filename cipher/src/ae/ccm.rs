use crate::block_cipher::{AES, AES128, AES192, AES256};
use crate::{AuthenticationCipher, BlockEncryptX, CipherError};
use std::fmt::Write as _;
use std::io::{Read, Write};

/// # Recommendation for Block Cipher Modes of Operation: The CCM Mode for Authentication and Confidentiality
///
/// - [NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final)
///
/// CCM(Counter with Cipher Block Chaining-Message Authentication Code) <br>
///
/// 记(Nonce, AssociateData, Payload)为`(N, A, P)`, 其字节长度为`(n, a, p)`. `Q`是表示`p`的字串,
/// 其字节长度记为`q`. MAC的字节长度记为`t`. 那么参数需要满足如下关系: <br>
/// - `t \in {4, 6, 8, 10, 12, 14, 16}`;
/// - `2 <= q <= 8`;
/// - `7 <= n <= 13`;
/// - `n + q = 15`;
/// - `a < 2^{64}`;
/// <br>
/// B0...Br每个长度都等于分组加密的块长度. <br>
/// B0是对Nonce和MAC长度, q长度和payload长度编码 <br>
/// B1...Bu是对关联数据的编码: 关联数据的长度编码 || 关联数据. Bu不足N补0对齐. <br>
/// B_{u+1}..Br是payload数据, Br不足N则补0对齐. <br>
/// 计数值Ctr_i是对计数值i的编码. <br>
///
/// ## 认证加密过程
///
/// - Y0 = CIPH_k(B0);
/// - Y_i = CIPH_k(Bi ^ Y_{i-1}), i=1..r;
/// - T = MSB_t(Y_r); # MAC的计算必须事先知道payload的长度, 因为其是编码到B0中的, 而且计算过程是链式的, 即依赖前一次的输出.
/// - 计算Ctr_i, i=0..m, m = (p + block_size - 1) / block_size;
/// - Sj = CIPH_k(Ctr_j), j=0..m;
/// - S = S1 || ... || Sm;
/// - C = (P ^ MSB_p(S)) || (T ^ MSB_t(S0));
///
/// ## 验证解密过程
///
/// - 密文C长度c小于`t`, 则验证失败;
/// - 计算Ctr_i, i=0..m, m = (c + block_size - 1) / block_size;
/// - Sj = CIPH_k(Ctr_j), j=0..m;
/// - S = S1 || ... || Sm;
/// - P = MSB_{c-t}(C) ^ MSB_{c-t}(S);
/// - T = LSB_t(C) ^ MSB_t(S0);
/// - 验证N, A, P是否合法, 合法则生成B0..Br;
/// - Y0 = CIPH_k(B0);
/// - Y_i = CIPH_k(Bi ^ Y_{i-1}), i=1..r;
/// - 验证`T`是否等于MSB_t(Y_r), 合法则返回P;
pub struct CCM<E> {
    cipher: E,
    mac_size: usize,
}

pub type AESCcm = CCM<AES>;
pub type AES128Ccm = CCM<AES128>;
pub type AES192Ccm = CCM<AES192>;
pub type AES256Ccm = CCM<AES256>;

impl<E: BlockEncryptX> CCM<E> {
    /// `mac_size` MAC的字节长度, 需满足`mac_size <= block_size`.
    pub fn new(cipher: E, mac_size: usize) -> Result<Self, CipherError> {
        Self::check_mac_size(&cipher, mac_size)?;

        Ok(Self { cipher, mac_size })
    }

    fn check_mac_size(cipher: &E, mac_size: usize) -> Result<(), CipherError> {
        if !(mac_size == 4
            || mac_size == 6
            || mac_size == 8
            || mac_size == 10
            || mac_size == 12
            || mac_size == 14
            || mac_size == 16)
        {
            Err(CipherError::AEError(format!(
                "Invalid MAC length `{mac_size}`, it should be the one of `{{4,6,8,10,12,14,16}}`"
            )))
        } else if cipher.block_size_x() < mac_size {
            Err(CipherError::AEError(format!("Invalid MAC length `{mac_size}, it should be less or equal to cipher block size `{}`", cipher.block_size_x())))
        } else {
            Ok(())
        }
    }

    fn check_nonce_size(nonce_size: usize) -> Result<(), CipherError> {
        if !(7..=13).contains(&nonce_size) {
            Err(CipherError::AEError(format!(
                "Invalid Nonce length `{}`, it should be in the range of `[7,13]`",
                nonce_size
            )))
        } else {
            Ok(())
        }
    }

    // 调用者保证参数是合法的
    fn check_payload_size(nonce_size: usize, payload_size: usize) -> Result<(), CipherError> {
        // 保存payload字节长度字串位长度
        let q = (Self::q_size(nonce_size) << 3) as u32;
        let payload_size_bits = usize::BITS - payload_size.leading_zeros();

        if payload_size_bits > q {
            Err(CipherError::AEError(format!("Invalid payload bits length `{payload_size_bits}, it should be less than `{q} when the nonce size is {}`", nonce_size)))
        } else {
            Ok(())
        }
    }

    fn check_para(nonce: &[u8], payload: &[u8]) -> Result<(), CipherError> {
        let (nonce_size, payload_size) = (nonce.len(), payload.len());
        Self::check_nonce_size(nonce_size)?;
        Self::check_payload_size(nonce_size, payload_size)
    }

    const fn q_size(nonce_size: usize) -> usize {
        15 - nonce_size
    }

    fn b0_flags(&self, is_adata: bool, nonce_size: usize) -> u8 {
        (if is_adata { 64 } else { 0 })
            | (((self.mac_size as u8 - 2) >> 1) << 3)
            | (Self::q_size(nonce_size) as u8 - 1)
    }

    fn b0(&self, is_adata: bool, nonce: &[u8], payload: &[u8], b0: &mut [u8]) {
        let q = Self::q_size(nonce.len());
        b0[0] = self.b0_flags(is_adata, nonce.len());
        b0[1..(1 + nonce.len())].copy_from_slice(nonce);

        let p = payload.len().to_be_bytes();
        b0[(self.cipher.block_size_x() - q)..]
            .iter_mut()
            .rev()
            .zip(p.into_iter().rev())
            .for_each(|(a, b)| {
                *a = b;
            });
    }

    // 返回编码后的长度, 调用者负责阶段
    fn encode_adata_len(&self, a: usize) -> Vec<u8> {
        let (mut out, x) = (
            Vec::with_capacity(self.cipher.block_size_x()),
            (a as u64).to_le_bytes(),
        );

        let l = if a < 0xff00 {
            2
        } else if a < u32::MAX as usize {
            out.push(0xff);
            out.push(0xfe);
            4
        } else {
            out.push(0xff);
            out.push(0xff);
            8
        };

        x.into_iter().take(l).rev().for_each(|y| {
            out.push(y);
        });

        out
    }

    fn counter_val(&self, nonce: &[u8], i: usize, out: &mut [u8]) {
        let q = Self::q_size(nonce.len()) as u8;
        out[0] = q - 1;
        out[1..(1 + nonce.len())].copy_from_slice(nonce);
        out[(self.cipher.block_size_x() - q as usize)..]
            .iter_mut()
            .rev()
            .zip((i as u64).to_le_bytes())
            .for_each(|(a, b)| {
                *a = b;
            });
    }
}

impl<E> Clone for CCM<E>
where
    E: Clone,
{
    fn clone(&self) -> Self {
        Self {
            mac_size: self.mac_size,
            cipher: self.cipher.clone(),
        }
    }
}

impl<E> CCM<E>
where
    E: BlockEncryptX,
{
    // 调用者负责截断到mac_size
    fn mac(&self, nonce: &[u8], adata: &[u8], payload: &[u8]) -> Result<Vec<u8>, CipherError> {
        Self::check_para(nonce, payload)?;
        let mut cipher = Vec::with_capacity(self.cipher.block_size_x());

        // B0
        let mut b0 = vec![0u8; self.cipher.block_size_x()];
        self.b0(!adata.is_empty(), nonce, payload, b0.as_mut_slice());
        self.cipher.encrypt_block_x(b0.as_slice(), &mut cipher)?;

        let fn_block_xor = |e: &E,
                            data: &[u8],
                            tmp: &mut Vec<u8>,
                            cipher: &mut Vec<u8>|
         -> Result<(), CipherError> {
            let mut itr = data.chunks_exact(e.block_size_x());
            for chunk in &mut itr {
                chunk
                    .iter()
                    .zip(cipher.iter_mut())
                    .for_each(|(&a, b)| *b ^= a);
                tmp.clear();
                tmp.append(cipher);
                e.encrypt_block_x(tmp.as_slice(), cipher)?;
            }

            if !itr.remainder().is_empty() {
                itr.remainder()
                    .iter()
                    .zip(cipher.iter_mut())
                    .for_each(|(&a, b)| *b ^= a);
                tmp.clear();
                tmp.append(cipher);
                e.encrypt_block_x(tmp.as_slice(), cipher)?;
            }

            Ok(())
        };

        // B1...Bu
        if !adata.is_empty() {
            let (mut b1, tmp) = (self.encode_adata_len(adata.len()), &mut b0);
            b1.extend_from_slice(adata);
            // 最后需要补0对齐到N的整数倍, 又由于和0异或亦是自身所以不用处理
            fn_block_xor(&self.cipher, b1.as_slice(), tmp, &mut cipher)?;
        }

        // payload
        let tmp = &mut b0;
        fn_block_xor(&self.cipher, payload, tmp, &mut cipher)?;

        // T ^ S_0
        tmp.clear();
        tmp.resize(self.cipher.block_size_x(), 0);
        self.counter_val(nonce, 0, tmp.as_mut_slice());
        let mut s0 = Vec::with_capacity(self.cipher.block_size_x());
        self.cipher.encrypt_block_x(tmp.as_slice(), &mut s0)?;
        s0.iter_mut()
            .zip(cipher)
            .take(self.mac_size)
            .for_each(|(a, b)| {
                *a ^= b;
            });

        Ok(s0)
    }
}

impl<E> AuthenticationCipher for CCM<E>
where
    E: BlockEncryptX,
{
    fn mac_size(&self) -> usize {
        self.mac_size
    }

    fn auth_encrypt_mac<R: Read, W: Write>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize, Vec<u8>), CipherError> {
        let mut payload = Vec::with_capacity(2048);
        in_data
            .read_to_end(&mut payload)
            .map_err(CipherError::from)?;

        let mac = self.mac(nonce, associated_data, payload.as_slice())?;

        //Sj
        let (mut cnt, mut sj) = (vec![], vec![]);
        for (i, chunk) in payload.chunks(self.cipher.block_size_x()).enumerate() {
            cnt.clear();
            cnt.resize(self.cipher.block_size_x(), 0);
            self.counter_val(nonce, i + 1, cnt.as_mut_slice());
            sj.clear();
            self.cipher.encrypt_block_x(cnt.as_slice(), &mut sj)?;
            // P ^ Sj
            sj.iter_mut().zip(chunk).for_each(|(a, &b)| {
                *a ^= b;
            });
            out_data
                .write_all(&sj[..chunk.len()])
                .map_err(CipherError::from)?;
        }

        out_data
            .write_all(&mac[..self.mac_size])
            .map_err(CipherError::from)?;

        Ok((
            payload.len(),
            payload.len() + self.mac_size,
            mac[..self.mac_size].to_vec(),
        ))
    }

    fn auth_decrypt<R: Read, W: Write>(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), CipherError> {
        Self::check_nonce_size(nonce.len())?;
        let mut ciphertext = Vec::with_capacity(2048);
        in_data
            .read_to_end(&mut ciphertext)
            .map_err(CipherError::from)?;

        if ciphertext.len() < self.mac_size {
            return Err(CipherError::AEError(format!(
                "ciphertext length `{}` less than MAC length `{}`",
                ciphertext.len(),
                self.mac_size
            )));
        }
        Self::check_payload_size(nonce.len(), ciphertext.len() - self.mac_size)?;

        // payload
        let (l, n, mut cnt, mut sj) =
            (ciphertext.len(), self.cipher.block_size_x(), vec![], vec![]);
        for (i, chunk) in ciphertext[..(l - self.mac_size)].chunks_mut(n).enumerate() {
            cnt.clear();
            cnt.resize(n, 0);
            self.counter_val(nonce, i + 1, cnt.as_mut_slice());
            sj.clear();
            self.cipher.encrypt_block_x(cnt.as_slice(), &mut sj)?;
            chunk.iter_mut().zip(sj.iter()).for_each(|(a, &b)| {
                *a ^= b;
            });
        }
        let payload = &ciphertext[..(ciphertext.len() - self.mac_size)];

        let mac = self.mac(nonce, associated_data, payload)?;
        let mac = &mac[..self.mac_size];
        let tgt = &ciphertext[(ciphertext.len() - self.mac_size)..];

        if tgt != mac {
            let (mac_tgt, mac) = (
                tgt.iter().fold(String::default(), |mut x, y| {
                    write!(&mut x, "{:02x}", y).unwrap();
                    x
                }),
                mac.iter().fold(String::default(), |mut x, y| {
                    write!(&mut x, "{:02x}", y).unwrap();
                    x
                }),
            );

            Err(CipherError::AEError(format!(
                "Invalid MAC value, {} != {}",
                mac_tgt, mac
            )))
        } else {
            out_data.write_all(payload).map_err(CipherError::from)?;
            Ok((ciphertext.len(), payload.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ae::CCM;
    use crate::block_cipher::AES;
    use crate::AuthenticationCipher;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn ccm_aes() {
        // (key, N, A, P, C)
        let cases = [
            (
                4usize,
                "404142434445464748494a4b4c4d4e4f",
                "10111213141516",
                "0001020304050607",
                "20212223",
                "7162015b4dac255d"
            ),
            (
                6,
                "404142434445464748494a4b4c4d4e4f",
                "1011121314151617",
                "000102030405060708090a0b0c0d0e0f",
                "202122232425262728292a2b2c2d2e2f",
                "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd",
            ),
            (
                8,
                "404142434445464748494a4b4c4d4e4f",
                "101112131415161718191a1b",
                "000102030405060708090a0b0c0d0e0f10111213",
                "202122232425262728292a2b2c2d2e2f3031323334353637",
                "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951",
            ),
            (
                14,
                "404142434445464748494a4b4c4d4e4f",
                "101112131415161718191a1b1c",
                // 重复256次
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b",
            ),
        ].into_iter().map(|(mac_size, key, n, a, p, c)| {
            let mut a = BigUint::from_str_radix(a, 16).unwrap().to_bytes_be();
            a.insert(0, 0x00);
            (
                mac_size,
                BigUint::from_str_radix(key, 16).unwrap().to_bytes_be(),
                BigUint::from_str_radix(n, 16).unwrap().to_bytes_be(),
                a,
                BigUint::from_str_radix(p, 16).unwrap().to_bytes_be(),
                BigUint::from_str_radix(c, 16).unwrap().to_bytes_be(),
            )
        }).collect::<Vec<_>>();

        for (i, (mac_size, key, n, mut a, p, c)) in cases.into_iter().enumerate() {
            let aes = AES::new(key.as_slice()).unwrap();
            let ccm = CCM::new(aes, mac_size).unwrap();
            if i == 3 {
                a = a.into_iter().cycle().take(524288 >> 3).collect::<Vec<_>>();
            }

            let (mut buf, mut pt) = (Vec::new(), p.as_slice());
            let (ilen, olen) = ccm
                .auth_encrypt(n.as_slice(), a.as_slice(), &mut pt, &mut buf)
                .unwrap();
            assert_eq!(ilen + mac_size, olen, "case {i} encrypt failed");
            assert_eq!(buf, c, "case {i} encrypt failed");

            buf.clear();
            let mut ct = c.as_slice();
            let (ilen, olen) = ccm
                .auth_decrypt(n.as_slice(), a.as_slice(), &mut ct, &mut buf)
                .unwrap();
            assert_eq!(ilen, olen + mac_size, "case {i} decrypt failed");
            assert_eq!(buf, p, "case {i} decrypt failed");
        }
    }
}
