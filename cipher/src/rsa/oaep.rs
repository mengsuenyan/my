//! = RFC 8017
//!
//! == PKCS #1: RSA Cryptography Specification Version 2.2
//!
//! === OAEP(Optimal Asymmetric Encryption Padding)
//!

use crate::block_cipher::{BlockDecryptX, BlockEncryptX};
use crate::rsa::FlagClear;
use crate::rsa::{PrivateKey, PublicKey};
use crate::{CipherError, Rand};
use crypto_hash::DigestX;
use num_bigint::BigUint;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

/// Optimal Asymmetric Encryption Padding
pub struct OAEPEncrypt<H: DigestX, R: Rand> {
    is_working: AtomicBool,
    key: PublicKey,
    hasher: RefCell<H>,
    rng: RefCell<R>,
    hlen: usize,
    label: Vec<u8>,
}

#[derive(Clone)]
pub struct OAEPDecrypt<H: DigestX, R: Rand> {
    de: OAEPEncrypt<H, R>,
    key: PrivateKey,
}

impl<'a, H: DigestX, R: Rand> From<&'a OAEPEncrypt<H, R>> for FlagClear<'a> {
    fn from(value: &'a OAEPEncrypt<H, R>) -> Self {
        Self {
            is_working: &value.is_working,
        }
    }
}

impl<H: DigestX, R: Rand> OAEPEncrypt<H, R> {
    /// label: 和消息相关联的标签
    pub fn new(key: PublicKey, hasher: H, rng: R, label: &[u8]) -> Result<Self, CipherError> {
        if key.modules().bits() & 7 != 0 {
            return Err(CipherError::Other(
                "rsa: the public key modulus bits must the multiple of 8".to_string(),
            ));
        }

        let (klen, hlen) = (
            (key.modules().bits() as usize + 7) >> 3,
            (hasher.digest_bits_x() + 7) >> 3,
        );
        if klen < (hlen << 1) + 2 {
            return Err(CipherError::Other(
                "rsa: the public key modulus is too short".to_string(),
            ));
        }
        key.is_valid()?;

        Ok(Self {
            is_working: AtomicBool::new(false),
            key,
            hasher: RefCell::new(hasher),
            rng: RefCell::new(rng),
            label: label.to_vec(),
            hlen,
        })
    }

    pub fn set_label(&mut self, label: &[u8]) -> Result<(), CipherError> {
        if self.is_working.load(Ordering::Acquire) {
            return Err(CipherError::BeWorking(true));
        }

        self.label.clear();
        self.label.extend_from_slice(label);

        Ok(())
    }

    fn check(&self) -> Result<FlagClear, CipherError> {
        if self.is_working.load(Ordering::Acquire) {
            return Err(CipherError::BeWorking(true));
        }

        self.is_working.store(true, Ordering::Release);
        Ok(FlagClear::from(self))
    }

    fn mgf1_xor(&self, msg: &mut [u8], obound: Range<usize>, sbound: Range<usize>) {
        let (mut done, mut cnt) = (0, 0u32);

        let mut hasher = self.hasher.borrow_mut();
        while done < obound.end - obound.start {
            let seed = &msg[sbound.clone()];
            hasher.reset_x();
            hasher.write_all(seed).unwrap();
            hasher.write_all(&cnt.to_be_bytes()).unwrap();
            let digest = hasher.finish_x();

            msg[obound.clone()]
                .iter_mut()
                .skip(done)
                .zip(digest.iter())
                .for_each(|(a, &b)| {
                    *a ^= b;
                    done += 1;
                });

            cnt += 1;
        }
    }

    pub fn key_len(&self) -> usize {
        (self.key.modules().bits() as usize + 7) >> 3
    }

    const fn hash_len(&self) -> usize {
        self.hlen
    }

    pub fn max_msg_len(&self) -> usize {
        self.key_len() - (self.hash_len() << 1) - 2
    }

    /// 返回Encrypt(msg)加密后的字节长度
    /// `msg`读出的数据长度超过`mlen=max_msg_len()`时, 会按`mlen`分块加密;
    /// 加密后的数据应该是`clen=key_len()`的整数倍;
    pub fn oaep_encrypt<IR: Read, OW: Write>(
        &self,
        msg: &mut IR,
        cipher: &mut OW,
    ) -> Result<usize, CipherError> {
        let _clear = self.check()?;

        let (mut data, mut olen) = (Vec::with_capacity(1024), 0);
        msg.read_to_end(&mut data)?;
        for block in data.chunks(self.max_msg_len()) {
            olen += self.encrypt_inner(block, cipher)?;
        }

        Ok(olen)
    }

    pub(super) fn encrypt_inner<OW: Write>(
        &self,
        msg: &[u8],
        cipher: &mut OW,
    ) -> Result<usize, CipherError> {
        let (klen, hlen) = (self.key_len(), self.hash_len());
        if msg.len() > self.max_msg_len() {
            return Err(CipherError::Other(
                "rsa: the message length is too big".to_string(),
            ));
        }

        let mut hasher = self.hasher.borrow_mut();
        hasher.reset_x();
        hasher.write_all(self.label.as_slice()).unwrap();
        let digest = hasher.finish_x();
        drop(hasher);

        // em = 0x00 || masked seed || masked db(data block)
        let (mut em, mut idx) = (vec![0u8; klen], 1);

        //seed
        let mut rng = self.rng.borrow_mut();
        rng.rand(&mut em.as_mut_slice()[idx..(hlen + idx)]);
        idx += hlen;

        // db = lhash || ps || 0x01 || M
        em.iter_mut()
            .skip(idx)
            .zip(digest.iter())
            .for_each(|(a, &b)| *a = b);
        idx += hlen;
        idx += self.max_msg_len() - msg.len();
        em[idx] = 0x01;
        idx += 1;
        if msg.len() + idx != klen {
            return Err(CipherError::Other(
                "rsa: the encoding message not equal to modulus length".to_string(),
            ));
        }
        em.as_mut_slice()[idx..].copy_from_slice(msg);

        let (seed_bound, db_bound) = (
            Range {
                start: 1,
                end: hlen + 1,
            },
            Range {
                start: hlen + 1,
                end: klen,
            },
        );
        // maskedDB = db ^ dbMask, dbMask = MGF(seed, db_bound.end - db_bound.start);
        self.mgf1_xor(em.as_mut_slice(), db_bound.clone(), seed_bound.clone());
        // maskedSeed = seed ^ seedMask, seedMask = MGF(maskedDB, seed_bound.end - seed_bound.start);
        self.mgf1_xor(em.as_mut_slice(), seed_bound, db_bound);

        let m = BigUint::from_bytes_be(em.as_slice());
        let mut c = self.key.rsaep(&m)?.to_bytes_be();
        let clen = c.len();
        c.resize(klen, 0);
        cipher.write_all(&c[(klen - clen)..])?;
        cipher.write_all(&c[..(klen - clen)])?;

        Ok(klen)
    }
}

impl<H: DigestX, R: Rand> OAEPDecrypt<H, R> {
    pub fn new(key: PrivateKey, hasher: H, rng: R, label: &[u8]) -> Result<Self, CipherError> {
        key.is_valid()?;
        let de = OAEPEncrypt::new(key.public_key().clone(), hasher, rng, label)?;

        Ok(Self { de, key })
    }

    /// 不检查`key`的合法性;
    pub fn new_uncheck(
        key: PrivateKey,
        hasher: H,
        rng: R,
        label: &[u8],
    ) -> Result<Self, CipherError> {
        let de = OAEPEncrypt::new(key.public_key().clone(), hasher, rng, label)?;

        Ok(Self { de, key })
    }

    pub fn from_oaep_encrypt(
        key: PrivateKey,
        oaep_encrypt: OAEPEncrypt<H, R>,
    ) -> Result<Self, CipherError> {
        if key.public_key() != &oaep_encrypt.key {
            Err(CipherError::Other(
                "rsa-oaep: encrypt public key not match to private key".to_string(),
            ))
        } else {
            Ok(Self {
                de: oaep_encrypt,
                key,
            })
        }
    }

    pub fn max_msg_len(&self) -> usize {
        self.de.max_msg_len()
    }

    pub fn key_len(&self) -> usize {
        self.de.key_len()
    }

    pub fn set_label(&mut self, label: &[u8]) -> Result<(), CipherError> {
        self.de.set_label(label)
    }

    /// 密文数据会按`clen=key_len()`分块解密
    pub fn oaep_decrypt<IR: Read, OW: Write>(
        &self,
        cipher: &mut IR,
        msg: &mut OW,
    ) -> Result<usize, CipherError> {
        let _clear = self.de.check()?;

        let (mut data, mut olen) = (Vec::with_capacity(1024), 0);
        cipher.read_to_end(&mut data)?;

        for block in data.chunks(self.key_len()) {
            olen += self.decrypt_inner(block, msg)?;
        }

        Ok(olen)
    }

    /// 返回解密后的字节长度
    pub(super) fn decrypt_inner<OW: Write>(
        &self,
        cipher: &[u8],
        msg: &mut OW,
    ) -> Result<usize, CipherError> {
        let (klen, hlen) = (self.de.key_len(), self.de.hash_len());
        if cipher.is_empty() {
            return Err(CipherError::Other(
                "rsa: the cipher data is empty".to_string(),
            ));
        }

        if klen < cipher.len() || klen < ((hlen << 1) + 2) {
            return Err(CipherError::Other(
                "rsa: the public key modulus length is too short".to_string(),
            ));
        }

        let c = BigUint::from_bytes_be(cipher);
        let mut m = self.key.rsadp(&c)?.to_bytes_be();
        let tmp = m.len();
        m.resize(klen, 0);
        m.rotate_right(klen - tmp);

        if m[0] != 0 {
            return Err(CipherError::ValidateFailed(
                "rsa: invalid message encoding format".to_string(),
            ));
        }

        let mut hasher = self.de.hasher.borrow_mut();
        hasher.reset_x();
        hasher.write_all(self.de.label.as_slice()).unwrap();
        let digest = hasher.finish_x();
        drop(hasher);

        let (seed_bound, db_bound) = (
            Range {
                start: 1,
                end: hlen + 1,
            },
            Range {
                start: hlen + 1,
                end: m.len(),
            },
        );
        // maskedSeed
        self.de
            .mgf1_xor(m.as_mut_slice(), seed_bound.clone(), db_bound.clone());
        // maskedDB
        self.de
            .mgf1_xor(m.as_mut_slice(), db_bound.clone(), seed_bound);

        if digest
            .iter()
            .zip(m[db_bound.clone()].iter().take(hlen))
            .any(|(&a, &b)| a != b)
        {
            return Err(CipherError::ValidateFailed(
                "rsa: invalid label hash value".to_string(),
            ));
        }

        let (bound, mut idx) = (
            Range {
                start: db_bound.start + hlen,
                end: db_bound.end,
            },
            db_bound.start + hlen,
        );
        for &x in m[bound].iter() {
            idx += 1;
            if x != 0x00 {
                if x != 0x01 {
                    return Err(CipherError::ValidateFailed(
                        "rsa: invalid message encoding format".to_string(),
                    ));
                }
                break;
            }
        }

        let len = m.len() - idx;
        msg.write_all(&m[idx..])?;
        Ok(len)
    }
}

impl<H: DigestX, R: Rand> AsRef<OAEPEncrypt<H, R>> for OAEPDecrypt<H, R> {
    fn as_ref(&self) -> &OAEPEncrypt<H, R> {
        &self.de
    }
}

impl<H: DigestX, R: Rand> AsRef<PublicKey> for OAEPEncrypt<H, R> {
    fn as_ref(&self) -> &PublicKey {
        &self.key
    }
}

impl<H: DigestX, R: Rand> AsRef<PrivateKey> for OAEPDecrypt<H, R> {
    fn as_ref(&self) -> &PrivateKey {
        &self.key
    }
}

impl<H: DigestX, R: Rand> From<OAEPDecrypt<H, R>> for OAEPEncrypt<H, R> {
    fn from(value: OAEPDecrypt<H, R>) -> Self {
        value.de
    }
}

impl<H, R> Clone for OAEPEncrypt<H, R>
where
    H: DigestX + Clone,
    R: Rand + Clone,
{
    fn clone(&self) -> Self {
        Self {
            is_working: Default::default(),
            key: self.key.clone(),
            hasher: self.hasher.clone(),
            rng: self.rng.clone(),
            label: self.label.clone(),
            hlen: self.hlen,
        }
    }
}

impl<H: DigestX, R: Rand> BlockEncryptX for OAEPEncrypt<H, R> {
    fn block_size_x(&self) -> usize {
        self.max_msg_len()
    }

    fn encrypt_block_x(
        &self,
        mut plaintext: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        let _len = self.oaep_encrypt(&mut plaintext, ciphertext)?;
        Ok(())
    }
}

impl<H: DigestX, R: Rand> BlockDecryptX for OAEPDecrypt<H, R> {
    fn block_size_x(&self) -> usize {
        self.key_len()
    }

    fn decrypt_block_x(
        &self,
        mut ciphertext: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        let _len = self.oaep_decrypt(&mut ciphertext, plaintext)?;
        Ok(())
    }
}

impl<H: DigestX, R: Rand> BlockEncryptX for OAEPDecrypt<H, R> {
    fn block_size_x(&self) -> usize {
        self.max_msg_len()
    }

    fn encrypt_block_x(
        &self,
        mut plaintext: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        let _len = self.de.oaep_encrypt(&mut plaintext, ciphertext)?;
        Ok(())
    }
}
