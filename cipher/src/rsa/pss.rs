//! = RFC 8017
//!
//! == PKCS #1: RSA Cryptography Specification Version 2.2
//!
//! === PSS(Probabilistic Signature Scheme)
//!

use crate::rsa::{PrivateKey, PublicKey};
use crate::{CipherError, Rand, Sign, Verify};
use crypto_hash::DigestX;
use num_bigint::BigUint;
use std::cell::RefCell;
use std::ops::Range;

pub struct PSSVerify<H: DigestX, R: Rand> {
    key: PublicKey,
    // salt len
    slen: usize,
    hlen: usize,
    hf: RefCell<H>,
    rd: RefCell<R>,
}

pub struct PSSSign<H: DigestX, R: Rand> {
    key: PrivateKey,
    pss: PSSVerify<H, R>,
}

impl<H: DigestX, R: Rand> AsRef<PSSVerify<H, R>> for PSSSign<H, R> {
    fn as_ref(&self) -> &PSSVerify<H, R> {
        &self.pss
    }
}

impl<H: DigestX, R: Rand> AsRef<PublicKey> for PSSVerify<H, R> {
    fn as_ref(&self) -> &PublicKey {
        &self.key
    }
}

impl<H: DigestX, R: Rand> AsRef<PrivateKey> for PSSSign<H, R> {
    fn as_ref(&self) -> &PrivateKey {
        &self.key
    }
}

impl<H: DigestX, R: Rand> From<PSSSign<H, R>> for PSSVerify<H, R> {
    fn from(value: PSSSign<H, R>) -> Self {
        value.pss
    }
}

impl<H: DigestX, R: Rand> PSSVerify<H, R> {
    /// `hasher`: message digest generator;
    /// `rd`: random number generator;
    /// `salt_len` the length of salt in bytes, `None` means the salt length equal
    /// to the `digest.len()`, `Some(0)` means that the salt length compute from the modulus bit length of public key.
    /// `Some(x)` means that the salt length equal to `x`;
    pub fn new(
        key: PublicKey,
        hasher: H,
        rng: R,
        salt_len: Option<usize>,
    ) -> Result<Self, CipherError> {
        if hasher.digest_bits_x() & 7 != 0 {
            return Err(CipherError::Other(
                "pss: hasher bits must be multiple of 8".to_string(),
            ));
        }
        let (klen, hlen) = (
            (key.modules().bits() as usize + 7) >> 3,
            (hasher.digest_bits_x() + 7) >> 3,
        );
        if klen < hlen + 2 {
            return Err(CipherError::Other(
                "pss: the public key is too short".to_string(),
            ));
        }
        key.is_valid()?;
        let slen = salt_len
            .map(|x| {
                if x > 0 {
                    x
                } else {
                    klen.saturating_sub(2 + hlen)
                }
            })
            .unwrap_or(hlen);

        let em_len = (key.modules().bits() as usize + 6) >> 3;
        if em_len < hlen + slen + 2 {
            return Err(CipherError::Other(
                "pss: the salt length is too long".to_string(),
            ));
        }

        Ok(Self {
            key,
            rd: RefCell::new(rng),
            hlen,
            hf: RefCell::new(hasher),
            slen,
        })
    }

    pub fn salt_len(&self) -> usize {
        self.slen
    }

    /// 公钥modulus占用的位数
    pub fn key_len(&self) -> usize {
        (self.key_bits() + 7) >> 3
    }

    pub fn em_len(&self) -> usize {
        (self.key_bits() - 1 + 7) >> 3
    }

    /// 编码消息的位数
    pub fn em_bits(&self) -> usize {
        self.key_bits() - 1
    }

    pub fn key_bits(&self) -> usize {
        self.key.modules().bits() as usize
    }

    pub fn hash_len(&self) -> usize {
        self.hlen
    }

    fn mgf1_xor(&self, em: &mut [u8]) {
        let (db_idx, h_idx) = self.idx_bound();
        let (mut done, mut count, out_len) = (0, 0u32, db_idx.end - db_idx.start);

        let mut hf = self.hf.borrow_mut();
        while done < out_len {
            hf.reset_x();
            hf.write_all(&em[h_idx.clone()]).unwrap();
            hf.write_all(count.to_be_bytes().as_ref()).unwrap();
            let d = hf.finish_x();

            em[db_idx.clone()]
                .iter_mut()
                .skip(done)
                .zip(d)
                .for_each(|(a, b)| {
                    *a ^= b;
                    done += 1;
                });

            count += 1;
        }
    }

    // (db_idx, hash_idx)
    fn idx_bound(&self) -> (Range<usize>, Range<usize>) {
        let (em_len, hlen) = (self.em_len(), self.hash_len());
        // em = maskedDB || H || 0xbc
        (
            Range {
                start: 0,
                end: em_len - hlen - 1,
            },
            Range {
                start: em_len - hlen - 1,
                end: em_len - 1,
            },
        )
    }

    fn emsa_pss_encode(&self, msg: &[u8], em: &mut Vec<u8>) -> Result<(), CipherError> {
        let (mut salt, mut rd) = (vec![0u8; self.slen], self.rd.borrow_mut());
        rd.rand(salt.as_mut_slice());
        self.emsa_pss_encode_with_salt(msg, salt.as_slice(), em)
    }

    // em.len() = klen
    // em = maskedDB || H || 0xbc
    // H = Hash(M')
    // M' = 0x00 || ... | 0x00 || Hash(msg) || salt
    // db = ps || 0x01 || salt
    // maskedDB = MGF(H, em.len - H.len - 1) ^ db
    fn emsa_pss_encode_with_salt(
        &self,
        msg: &[u8],
        salt: &[u8],
        em: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        let (em_len, slen) = (self.em_len(), self.slen);

        em.clear();
        em.resize(em_len, 0);

        let mut hasher = self.hf.borrow_mut();
        hasher.reset_x();
        hasher.write_all(msg).unwrap();
        let h_msg = hasher.finish_x();

        // H = Hash(M')
        hasher.reset_x();
        hasher.write_all([0u8; 8].as_slice()).unwrap();
        hasher.write_all(h_msg.as_slice()).unwrap();
        hasher.write_all(salt).unwrap();
        let h_msg = hasher.finish_x();
        drop(hasher);

        // em = maskedDB || H || 0xbc
        let (db_idx, h_idx) = self.idx_bound();
        em[h_idx.clone()].copy_from_slice(h_msg.as_slice());
        em[h_idx.end] = 0xbc;
        // db = ps || 0x01 || salt
        em[db_idx.end - slen - 1] = 0x01;
        em[(db_idx.end - slen)..db_idx.end].copy_from_slice(salt);
        self.mgf1_xor(em.as_mut_slice());
        em[0] &= 0xffu8 >> ((em_len << 3) - self.em_bits());

        Ok(())
    }

    fn emsa_pss_verify(&self, msg: &[u8], em: &mut [u8]) -> Result<(), CipherError> {
        let (em_len, slen) = (self.em_len(), self.slen);

        if em.len() != em_len {
            return Err(CipherError::ValidateFailed(
                "pss: Invalid encode message length".to_string(),
            ));
        }

        if em[em_len - 1] != 0xbc {
            return Err(CipherError::ValidateFailed(
                "pss: invalid tail flag".to_string(),
            ));
        } else if (em[0] & (0xffu8 << (8 - ((em_len << 3) - self.em_bits())))) != 0 {
            return Err(CipherError::ValidateFailed(
                "pss: invalid head tag".to_string(),
            ));
        }

        let (db_idx, h_idx) = self.idx_bound();
        self.mgf1_xor(em);
        em[0] &= 0xffu8 >> ((em_len << 3) - self.em_bits());

        // db = ps || 0x01 || salt
        if em.iter().take(db_idx.end - slen - 1).any(|&a| a != 0) {
            return Err(CipherError::ValidateFailed(
                "pss: invalid db head".to_string(),
            ));
        } else if em[db_idx.end - slen - 1] != 0x01 {
            return Err(CipherError::ValidateFailed(
                "pss: invalid db body".to_string(),
            ));
        }

        let mut hasher = self.hf.borrow_mut();
        hasher.reset_x();
        hasher.write_all(msg).unwrap();
        let h_msg = hasher.finish_x();
        hasher.reset_x();
        hasher.write_all([0u8; 8].as_slice()).unwrap();
        hasher.write_all(h_msg.as_slice()).unwrap();
        hasher
            .write_all(&em[(db_idx.end - slen)..db_idx.end])
            .unwrap();
        let h_msg = hasher.finish_x();

        if h_msg != em[h_idx] {
            return Err(CipherError::ValidateFailed(
                "pss: invalid signature".to_string(),
            ));
        }

        Ok(())
    }

    fn verify_inner(&self, msg: &[u8], signature: &[u8]) -> Result<(), CipherError> {
        let s = BigUint::from_bytes_be(signature);
        let m = self.key.rsaep(&s)?;
        if self.em_len() < ((m.bits() as usize + 7) >> 3) {
            return Err(CipherError::ValidateFailed(
                "pss: invalid encoding message length".to_string(),
            ));
        }

        let mut em = m.to_bytes_be();
        let len = em.len();
        em.resize(self.em_len(), 0);
        em.rotate_right(self.em_len() - len);
        self.emsa_pss_verify(msg, em.as_mut_slice())
    }
}

impl<H: DigestX, R: Rand> PSSSign<H, R> {
    /// `hasher`: message digest generator;
    /// `rd`: random number generator;
    /// `salt_len` the length of salt in bytes, `None` means the salt length equal
    /// to the `digest.len()`, `Some(0)` means that the salt length compute from the modulus bit length of public key.
    /// `Some(x)` means that the salt length equal to `x`;
    pub fn new(
        key: PrivateKey,
        hasher: H,
        rng: R,
        salt_len: Option<usize>,
    ) -> Result<Self, CipherError> {
        let pss = PSSVerify::new(key.public_key().clone(), hasher, rng, salt_len)?;
        key.is_valid()?;
        Ok(Self { pss, key })
    }

    /// 不检查key的合法性, 无需`n`的因子`p,q`
    pub fn new_uncheck(
        key: PrivateKey,
        hasher: H,
        rng: R,
        salt_len: Option<usize>,
    ) -> Result<Self, CipherError> {
        let pss = PSSVerify::new(key.public_key().clone(), hasher, rng, salt_len)?;
        Ok(Self { pss, key })
    }

    pub fn salt_len(&self) -> usize {
        self.pss.salt_len()
    }

    pub fn key_len(&self) -> usize {
        self.pss.key_len()
    }

    pub fn key_bits(&self) -> usize {
        self.pss.key_bits()
    }

    pub fn em_len(&self) -> usize {
        self.pss.em_len()
    }

    pub fn em_bits(&self) -> usize {
        self.pss.em_bits()
    }

    pub fn hash_len(&self) -> usize {
        self.pss.hash_len()
    }

    fn sign_inner(&self, msg: &[u8], signature: &mut Vec<u8>) -> Result<(), CipherError> {
        let mut em = vec![];
        self.pss.emsa_pss_encode(msg, &mut em)?;
        let m = BigUint::from_bytes_be(em.as_slice());
        let c = self.key.rsadp(&m)?;
        let mut s = c.to_bytes_be();
        signature.extend(std::iter::repeat(0).take(self.key_len() - s.len()));
        signature.append(&mut s);
        Ok(())
    }
}

impl<H: DigestX, R: Rand> Verify for PSSVerify<H, R> {
    fn verify(&self, msg: &[u8], sign: &[u8]) -> Result<(), CipherError> {
        self.verify_inner(msg, sign)
    }
}

impl<H: DigestX, R: Rand> Verify for PSSSign<H, R> {
    fn verify(&self, msg: &[u8], sign: &[u8]) -> Result<(), CipherError> {
        self.pss.verify_inner(msg, sign)
    }
}

impl<H: DigestX, R: Rand> Sign for PSSSign<H, R> {
    fn sign(&self, msg: &[u8], sign: &mut Vec<u8>) -> Result<(), CipherError> {
        self.sign_inner(msg, sign)
    }
}

#[cfg(test)]
mod tests {
    use crate::rand::DefaultRand;
    use crate::rsa::{PSSSign, PSSVerify, PrivateKey, PublicKey};
    use crate::{Sign, Verify};
    use crypto_hash::sha2::{SHA1, SHA256};
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn emsa_pss() {
        let msg = vec![
            0x85u8, 0x9e, 0xef, 0x2f, 0xd7, 0x8a, 0xca, 0x00, 0x30, 0x8b, 0xdc, 0x47, 0x11, 0x93,
            0xbf, 0x55, 0xbf, 0x9d, 0x78, 0xdb, 0x8f, 0x8a, 0x67, 0x2b, 0x48, 0x46, 0x34, 0xf3,
            0xc9, 0xc2, 0x6e, 0x64, 0x78, 0xae, 0x10, 0x26, 0x0f, 0xe0, 0xdd, 0x8c, 0x08, 0x2e,
            0x53, 0xa5, 0x29, 0x3a, 0xf2, 0x17, 0x3c, 0xd5, 0x0c, 0x6d, 0x5d, 0x35, 0x4f, 0xeb,
            0xf7, 0x8b, 0x26, 0x02, 0x1c, 0x25, 0xc0, 0x27, 0x12, 0xe7, 0x8c, 0xd4, 0x69, 0x4c,
            0x9f, 0x46, 0x97, 0x77, 0xe4, 0x51, 0xe7, 0xf8, 0xe9, 0xe0, 0x4c, 0xd3, 0x73, 0x9c,
            0x6b, 0xbf, 0xed, 0xae, 0x48, 0x7f, 0xb5, 0x56, 0x44, 0xe9, 0xca, 0x74, 0xff, 0x77,
            0xa5, 0x3c, 0xb7, 0x29, 0x80, 0x2f, 0x6e, 0xd4, 0xa5, 0xff, 0xa8, 0xba, 0x15, 0x98,
            0x90, 0xfc,
        ];
        let salt = vec![
            0xe3u8, 0xb5, 0xd5, 0xd0, 0x02, 0xc1, 0xbc, 0xe5, 0x0c, 0x2b, 0x65, 0xef, 0x88, 0xa1,
            0x88, 0xd8, 0x3b, 0xce, 0x7e, 0x61,
        ];
        let expected = vec![
            0x66u8, 0xe4, 0x67, 0x2e, 0x83, 0x6a, 0xd1, 0x21, 0xba, 0x24, 0x4b, 0xed, 0x65, 0x76,
            0xb8, 0x67, 0xd9, 0xa4, 0x47, 0xc2, 0x8a, 0x6e, 0x66, 0xa5, 0xb8, 0x7d, 0xee, 0x7f,
            0xbc, 0x7e, 0x65, 0xaf, 0x50, 0x57, 0xf8, 0x6f, 0xae, 0x89, 0x84, 0xd9, 0xba, 0x7f,
            0x96, 0x9a, 0xd6, 0xfe, 0x02, 0xa4, 0xd7, 0x5f, 0x74, 0x45, 0xfe, 0xfd, 0xd8, 0x5b,
            0x6d, 0x3a, 0x47, 0x7c, 0x28, 0xd2, 0x4b, 0xa1, 0xe3, 0x75, 0x6f, 0x79, 0x2d, 0xd1,
            0xdc, 0xe8, 0xca, 0x94, 0x44, 0x0e, 0xcb, 0x52, 0x79, 0xec, 0xd3, 0x18, 0x3a, 0x31,
            0x1f, 0xc8, 0x96, 0xda, 0x1c, 0xb3, 0x93, 0x11, 0xaf, 0x37, 0xea, 0x4a, 0x75, 0xe2,
            0x4b, 0xdb, 0xfd, 0x5c, 0x1d, 0xa0, 0xde, 0x7c, 0xec, 0xdf, 0x1a, 0x89, 0x6f, 0x9d,
            0x8b, 0xc8, 0x16, 0xd9, 0x7c, 0xd7, 0xa2, 0xc4, 0x3b, 0xad, 0x54, 0x6f, 0xbe, 0x8c,
            0xfe, 0xbc,
        ];

        let (n, e, d, p, q) = (
            BigUint::from_str_radix("a5e198f3b1619971e077ce9186615d47cc45340d7d1f8c4fa8f998884f934f62513c91c7b796f508b4090fc285c0c5ff57d722b4044d5f25f4dcd397b8360f3f440fc96473ec4ec9f39bf9eacc94d858f357b6ca19c239041f29153cea96a42c0ce032c5c6e65a328983268344798376492ed5c2d27392176db8920099e8ac0d", 16).unwrap(),
            BigUint::from(0x10001u32),
            BigUint::from_str_radix("77db0681e603c83450e5201b64064bb909ee62caf04270464aa875bee008674e79b612fb443acdb7c925d6fe4d585977c3074e2ad604f59fde4a0494d6643124f245132b34b1ebbe86d6224a003af425d26300cdb1089bef63f44c3d9ea34143045a3e1ee73f917cbeb7b96641a539b3f777cd081d69e9fbe0f7b081bd0a361d", 16).unwrap(),
            BigUint::from_str_radix("c5d940adfaee20d634f1aed7768dc40b050873f75e4d2eb192eba01db5896a90c4362c7a3f83cd3116aebc178dcb00cb321d760d9c9edfe4fb191f6c169b8c5b", 16).unwrap(),
            BigUint::from_str_radix("d6a304998f9c9c81afdc04d39adab29ef4c98574cfa73464bee5dc16c36e1d95b2276e0486f49020f5d06b7dc524032c3a2929f2f25c7b482e52bc835861b5b7", 16).unwrap(),
            );
        let (pk, key) = (
            PublicKey::new_uncheck(n, e),
            PrivateKey::new_uncheck_with_factor(d, p, q, vec![]),
        );
        assert_eq!(&pk, key.public_key());

        let (sha1, rd) = (SHA1::new(), DefaultRand::default());
        let pss = PSSVerify::new(key.public_key().clone(), sha1, rd, Some(salt.len())).unwrap();

        let mut em = Vec::with_capacity(expected.len());
        pss.emsa_pss_encode_with_salt(msg.as_slice(), salt.as_slice(), &mut em)
            .unwrap();

        assert_eq!(em, expected);

        pss.emsa_pss_verify(msg.as_slice(), em.as_mut_slice())
            .unwrap();
    }

    #[test]
    fn emsa_pss_openssl() {
        let (msg, sig) = (
            "testing",
            vec![
                0x95u8, 0x59, 0x6f, 0xd3, 0x10, 0xa2, 0xe7, 0xa2, 0x92, 0x9d, 0x4a, 0x07, 0x2e,
                0x2b, 0x27, 0xcc, 0x06, 0xc2, 0x87, 0x2c, 0x52, 0xf0, 0x4a, 0xcc, 0x05, 0x94, 0xf2,
                0xc3, 0x2e, 0x20, 0xd7, 0x3e, 0x66, 0x62, 0xb5, 0x95, 0x2b, 0xa3, 0x93, 0x9a, 0x66,
                0x64, 0x25, 0xe0, 0x74, 0x66, 0x8c, 0x3e, 0x92, 0xeb, 0xc6, 0xe6, 0xc0, 0x44, 0xf3,
                0xb4, 0xb4, 0x2e, 0x8c, 0x66, 0x0a, 0x37, 0x9c, 0x69,
            ],
        );

        let (n, e, d, p, q) = (
            BigUint::from_str_radix("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10).unwrap(),
            BigUint::from(65537u32),
            BigUint::from_str_radix("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10).unwrap(),
            BigUint::from_str_radix("98920366548084643601728869055592650835572950932266967461790948584315647051443", 10).unwrap(),
            BigUint::from_str_radix("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10).unwrap(),
        );
        let (pk, key) = (
            PublicKey::new_uncheck(n, e),
            PrivateKey::new_uncheck_with_factor(d, p, q, vec![]),
        );
        assert_eq!(&pk, key.public_key());

        let (sha256, rd) = (SHA256::new(), DefaultRand::default());
        let pss = PSSSign::new(key, sha256, rd, Some(0)).unwrap();

        pss.verify(msg.as_bytes(), sig.as_slice()).unwrap();
        let mut signature = vec![];
        pss.sign(msg.as_bytes(), &mut signature).unwrap();
        pss.verify(msg.as_bytes(), signature.as_slice()).unwrap();
    }
}
