//! RFC 2898
//! PCKS #5: Password-Based Cryptography Specification Version 2.0
//!
//! RFC 8018
//! PCKS #5: Password-Based Cryptography Specification Version 2.1
//!

use crate::{CipherError, KDF, PRF};
use crypto_hash::DigestX;
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

#[derive(Clone)]
pub struct PBKDF1<D: DigestX> {
    password: Vec<u8>,
    salt: Vec<u8>,
    itr_cnt: usize,
    hf: D,
}

#[derive(Clone)]
pub struct PBKDF2<P: PRF> {
    hlen: usize,
    itr_cnt: usize,
    password: Vec<u8>,
    salt: Vec<u8>,
    prf: P,
}

impl<D: DigestX> PBKDF1<D> {
    pub fn new(
        digest: D,
        password: Vec<u8>,
        salt: Vec<u8>,
        iteration_count: usize,
    ) -> Result<Self, CipherError> {
        if digest.block_bits_x() & 7 != 0 {
            return Err(CipherError::Other(
                "digest bits must be multiple of 8".to_string(),
            ));
        } else if iteration_count == 0 {
            return Err(CipherError::Other(
                "iteration count must be not equal to 0".to_string(),
            ));
        } else if password.is_empty() {
            return Err(CipherError::Other("password must be not empty".to_string()));
        }

        Ok(Self {
            password,
            salt,
            itr_cnt: iteration_count,
            hf: digest,
        })
    }
}

impl<P: PRF> PBKDF2<P> {
    pub fn new(
        mut prf: P,
        password: Vec<u8>,
        salt: Vec<u8>,
        iteration_count: usize,
    ) -> Result<Self, CipherError> {
        if iteration_count == 0 {
            return Err(CipherError::Other(
                "iteration count must be not equal to 0".to_string(),
            ));
        }

        let hlen = prf.prf(&[]).len();
        if hlen == 0 {
            return Err(CipherError::Other(
                "inner error: cannot get hlen for PBKDF2".to_string(),
            ));
        }

        Ok(Self {
            hlen,
            salt,
            password,
            itr_cnt: iteration_count,
            prf,
        })
    }
}

impl<D: DigestX> Drop for PBKDF1<D> {
    fn drop(&mut self) {
        self.password.zeroize();
        self.salt.zeroize();
        self.itr_cnt.zeroize();
    }
}

impl<P: PRF> Drop for PBKDF2<P> {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.itr_cnt.zeroize();
    }
}

impl<D: DigestX> KDF for PBKDF1<D> {
    fn max_key_size(&self) -> usize {
        (self.hf.digest_bits_x() + 7) >> 3
    }

    fn kdf(&mut self, key_size: usize) -> Result<Vec<u8>, CipherError> {
        if key_size > self.max_key_size() {
            return Err(CipherError::InvalidKeySize {
                target: Some(key_size),
                real: self.max_key_size(),
            });
        }

        let mut ti = self.password.clone();
        ti.extend_from_slice(self.salt.as_slice());
        for _ in 0..self.itr_cnt {
            ti = self.hf.digest(ti.as_slice());
        }

        ti.truncate(key_size);
        Ok(ti)
    }
}

impl<P: PRF> KDF for PBKDF2<P> {
    fn max_key_size(&self) -> usize {
        u32::MAX as usize * self.hlen
    }

    fn kdf(&mut self, key_size: usize) -> Result<Vec<u8>, CipherError> {
        if key_size == 0 {
            return Err(CipherError::Other("key size can not be zero".to_string()));
        } else if key_size > self.max_key_size() {
            return Err(CipherError::InvalidKeySize {
                target: Some(key_size),
                real: self.max_key_size(),
            });
        }

        self.prf.update_key(self.password.clone())?;

        let l = (key_size + self.hlen - 1) / self.hlen;
        let mut f = vec![];
        for i in 1..=(l as u32) {
            let mut pre_ui = self.salt.clone();
            pre_ui.extend(i.to_be_bytes());
            pre_ui = self.prf.prf(pre_ui.as_slice());
            f.extend_from_slice(pre_ui.as_slice());
            for _ in 0..(self.itr_cnt - 1) {
                pre_ui = self.prf.prf(pre_ui.as_slice());
                f.iter_mut()
                    .rev()
                    .zip(pre_ui.iter().rev())
                    .for_each(|(a, b)| *a ^= b);
            }
        }
        f.truncate(key_size);
        Ok(f)
    }
}

#[cfg(test)]
mod tests {
    use crate::kdf::pbkdf::PBKDF2;
    use crate::prf::HMAC;
    use crate::KDF;
    use crypto_hash::sha2::SHA256;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn pbkdf2_hmac_sha2_256() {
        let sha256 = SHA256::new();
        let hmac = HMAC::new(sha256, vec![]).unwrap();
        let salt = BigUint::from_str_radix("aaef2d3f4d77ac66e9c5a6c3d8f921d1", 16)
            .unwrap()
            .to_bytes_be();
        let mut pbkdf2 =
            PBKDF2::new(hmac.clone(), "p@$Sw0rD~1".as_bytes().to_vec(), salt, 50000).unwrap();
        let key = pbkdf2.kdf(32).unwrap();
        let tgt = BigUint::from_str_radix(
            "52c5efa16e7022859051b1dec28bc65d9696a3005d0f97e506c42843bc3bdbc0",
            16,
        )
        .unwrap()
        .to_bytes_be();
        assert_eq!(key, tgt);

        let mut pbkdf2 = PBKDF2::new(
            hmac.clone(),
            "passwd".as_bytes().to_vec(),
            "salt".as_bytes().to_vec(),
            1,
        )
        .unwrap();
        let tgt = [
            0x55u8, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44,
            0xb6, 0x05, 0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57,
            0xc2, 0x0d, 0xac, 0xbc, 0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45, 0x99, 0x16,
            0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31, 0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5,
            0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83,
        ];
        let key = pbkdf2.kdf(64).unwrap();
        assert_eq!(key, tgt);

        let mut pbkdf2 = PBKDF2::new(
            hmac.clone(),
            "Password".as_bytes().to_vec(),
            "NaCl".as_bytes().to_vec(),
            80000,
        )
        .unwrap();
        let tgt = [
            0x4du8, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27,
            0x01, 0xf9, 0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14, 0xae, 0xff, 0x08, 0x87,
            0x6b, 0x34, 0xab, 0x56, 0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54, 0x9a, 0xdb,
            0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17, 0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78,
            0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d,
        ];
        let key = pbkdf2.kdf(64).unwrap();
        assert_eq!(key, tgt);
    }
}
