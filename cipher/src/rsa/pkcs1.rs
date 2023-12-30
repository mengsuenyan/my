//! = RFC 8017
//!
//! == PKCS #1: RSA Cryptography Specification Version 2.2
//!
//! === PKCS1(Public Key Cryptography Standards v1.5)
//!

use crate::block_cipher::{BlockDecryptX, BlockEncryptX};
use crate::rsa::flag::FlagClear;
use crate::rsa::{PrivateKey, PublicKey};
use crate::{CipherError, Decrypt, Encrypt, Rand};
use num_bigint::BigUint;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

pub struct PKCS1Encrypt<R: Rand> {
    is_working: AtomicBool,
    key: PublicKey,
    rng: RefCell<R>,
}

#[derive(Clone)]
pub struct PKCS1Decrypt<R: Rand> {
    key: PrivateKey,
    pkcs: PKCS1Encrypt<R>,
}

impl<R: Rand + Clone> Clone for PKCS1Encrypt<R> {
    fn clone(&self) -> Self {
        Self {
            rng: self.rng.clone(),
            key: self.key.clone(),
            is_working: AtomicBool::default(),
        }
    }
}

impl<'a, R: Rand> From<&'a PKCS1Encrypt<R>> for FlagClear<'a> {
    fn from(value: &'a PKCS1Encrypt<R>) -> Self {
        Self {
            is_working: &value.is_working,
        }
    }
}

impl<R: Rand> From<PKCS1Decrypt<R>> for PKCS1Encrypt<R> {
    fn from(value: PKCS1Decrypt<R>) -> Self {
        value.pkcs
    }
}

impl<R: Rand> AsRef<PKCS1Encrypt<R>> for PKCS1Decrypt<R> {
    fn as_ref(&self) -> &PKCS1Encrypt<R> {
        &self.pkcs
    }
}

impl<R: Rand> PKCS1Encrypt<R> {
    pub fn new(key: PublicKey, rng: R) -> Result<Self, CipherError> {
        if key.modules().bits() & 7 != 0 {
            return Err(CipherError::Other(
                "rsa: the public key modulus bits must the multiple of 8".to_string(),
            ));
        }

        let klen = (key.modules().bits() as usize + 7) >> 3;
        if klen <= 11 {
            return Err(CipherError::Other(
                "rsa: the public key is too short".to_string(),
            ));
        }

        key.is_valid()?;

        Ok(Self {
            is_working: AtomicBool::new(false),
            key,
            rng: RefCell::new(rng),
        })
    }

    pub fn key_len(&self) -> usize {
        (self.key.modules().bits() as usize + 7) >> 3
    }

    pub fn max_msg_len(&self) -> usize {
        self.key_len() - 11
    }

    fn check(&self) -> Result<FlagClear, CipherError> {
        if self.is_working.load(Ordering::Acquire) {
            return Err(CipherError::BeWorking(true));
        }

        self.is_working.store(true, Ordering::Release);
        Ok(FlagClear::from(self))
    }

    /// 返回Encrypt(msg)加密后的字节长度
    /// `msg`读出的数据长度超过`mlen=max_msg_len()`时, 会按`mlen`分块加密;
    /// 加密后的数据应该是`clen=key_len()`的整数倍;
    pub fn pkcs1_encrypt<IR: Read, OW: Write>(
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
        if msg.len() > self.max_msg_len() {
            return Err(CipherError::Other(
                "rsa: the message length is too big".to_string(),
            ));
        }

        let klen = self.key_len();
        // em = 0x00 || 0x02 || ps || 0x00 || msg
        let (mut em, mut idx, rng_len) = (vec![0u8; klen], 1, klen - msg.len() - 3);
        em[idx] = 0x02;
        idx += 1;
        let ps = &mut em.as_mut_slice()[idx..(idx + rng_len)];
        let mut rng = self.rng.borrow_mut();
        loop {
            rng.rand(ps);
            if !ps.iter().any(|&x| x == 0) {
                break;
            }
        }
        idx += rng_len + 1;
        em[idx..].copy_from_slice(msg);

        let m = BigUint::from_bytes_be(em.as_slice());
        let mut c = self.key.rsaep(&m)?.to_bytes_be();
        let clen = c.len();
        c.resize(klen, 0);
        cipher.write_all(&c[(klen - clen)..])?;
        cipher.write_all(&c[..(klen - clen)])?;

        Ok(klen)
    }
}

impl<R: Rand> PKCS1Decrypt<R> {
    pub fn new(key: PrivateKey, rng: R) -> Result<Self, CipherError> {
        let pkcs = PKCS1Encrypt::new(key.public_key().clone(), rng)?;
        key.is_valid()?;
        Ok(Self { pkcs, key })
    }

    /// 不检查`key`的合法性;
    pub fn new_uncheck(key: PrivateKey, rng: R) -> Result<Self, CipherError> {
        let pkcs = PKCS1Encrypt::new(key.public_key().clone(), rng)?;
        Ok(Self { pkcs, key })
    }

    pub fn key_len(&self) -> usize {
        self.pkcs.key_len()
    }

    pub fn max_msg_len(&self) -> usize {
        self.pkcs.max_msg_len()
    }

    /// 密文数据会按`clen=key_len()`分块解密
    pub fn pkcs_decrypt<IR: Read, OW: Write>(
        &self,
        cipher: &mut IR,
        msg: &mut OW,
    ) -> Result<usize, CipherError> {
        let _clear = self.pkcs.check()?;

        let (mut data, mut olen) = (Vec::with_capacity(1024), 0);
        cipher.read_to_end(&mut data)?;

        for block in data.chunks(self.key_len()) {
            olen += self.decrypt_inner(block, msg)?;
        }

        Ok(olen)
    }

    pub(super) fn decrypt_inner<OW: Write>(
        &self,
        cipher: &[u8],
        msg: &mut OW,
    ) -> Result<usize, CipherError> {
        let klen = self.key_len();

        if cipher.len() > klen {
            return Err(CipherError::Other("rsa: invalid cipher length".to_string()));
        }

        let c = BigUint::from_bytes_be(cipher);
        // em = 0x00 || 0x02 || ps || 0x00 || msg
        let mut em = self.key.rsadp(&c)?.to_bytes_be();
        let len = em.len();
        em.resize(klen, 0);
        em.rotate_right(klen - len);

        if em[0] != 0x00 || em[1] != 0x02 {
            return Err(CipherError::ValidateFailed(
                "rsa: invalid message encoding format".to_string(),
            ));
        }

        let mut idx = em
            .iter()
            .enumerate()
            .skip(2)
            .find(|x| *x.1 == 0)
            .map(|x| x.0)
            .unwrap_or_default();

        if idx < 10 {
            return Err(CipherError::ValidateFailed(
                "rsa: invalid message encoding format".to_string(),
            ));
        }

        idx += 1;
        msg.write_all(&em[idx..])?;
        Ok(em.len() - idx)
    }
}

impl<R: Rand> BlockEncryptX for PKCS1Encrypt<R> {
    fn block_size_x(&self) -> usize {
        self.max_msg_len()
    }
    fn encrypt_block_x(
        &self,
        mut plaintext: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        let _len = self.pkcs1_encrypt(&mut plaintext, ciphertext)?;
        Ok(())
    }
}

impl<R: Rand> BlockEncryptX for PKCS1Decrypt<R> {
    fn block_size_x(&self) -> usize {
        self.max_msg_len()
    }

    fn encrypt_block_x(
        &self,
        mut plaintext: &[u8],
        ciphertext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        let _len = self.pkcs.pkcs1_encrypt(&mut plaintext, ciphertext)?;
        Ok(())
    }
}

impl<R: Rand> BlockDecryptX for PKCS1Decrypt<R> {
    fn block_size_x(&self) -> usize {
        self.key_len()
    }

    fn decrypt_block_x(
        &self,
        mut ciphertext: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), CipherError> {
        let _len = self.pkcs_decrypt(&mut ciphertext, plaintext)?;
        Ok(())
    }
}

impl<R: Rand> Encrypt for PKCS1Encrypt<R> {
    fn encrypt(&self, plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), CipherError> {
        self.encrypt_block_x(plaintext, ciphertext)
    }
}

impl<R: Rand> Encrypt for PKCS1Decrypt<R> {
    fn encrypt(&self, plaintext: &[u8], ciphertext: &mut Vec<u8>) -> Result<(), CipherError> {
        self.encrypt_block_x(plaintext, ciphertext)
    }
}

impl<R: Rand> Decrypt for PKCS1Decrypt<R> {
    fn decrypt(&self, ciphertext: &[u8], plaintext: &mut Vec<u8>) -> Result<(), CipherError> {
        self.decrypt_block_x(ciphertext, plaintext)
    }
}

#[cfg(test)]
mod tests {
    use crate::rand::DefaultRand;
    use crate::rsa::{
        PKCS1Decrypt, PKCS1DecryptSteam, PKCS1Encrypt, PKCS1EncryptStream, PrivateKey,
    };
    use crate::{StreamDecrypt, StreamEncrypt};
    use encode::Decode;
    use num_bigint::BigUint;
    use num_traits::Num;

    fn key() -> PrivateKey {
        let (n, _e, d,p, q) = (
            BigUint::from_str_radix("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10).unwrap(),
            BigUint::from(65537u32),
            BigUint::from_str_radix("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10).unwrap(),
            BigUint::from_str_radix("98920366548084643601728869055592650835572950932266967461790948584315647051443", 10).unwrap(),
            BigUint::from_str_radix("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10).unwrap(),
            );

        let key = PrivateKey::new_uncheck_with_factor(d, p, q, Vec::with_capacity(0));
        assert_eq!(key.public_key().modules(), &n);
        key
    }

    #[test]
    fn pkcs1_encrypt_decrypt() {
        // (ciphertext, decrypt_msg)
        let cases = [
            ("gIcUIoVkD6ATMBk/u/nlCZCCWRKdkfjCgFdo35VpRXLduiKXhNz1XupLLzTXAybEq15juc+EgY5o0DHv/nt3yg==", "x"),
            ("Y7TOCSqofGhkRb+jaVRLzK8xw2cSo1IVES19utzv6hwvx+M8kFsoWQm5DzBeJCZTCVDPkTpavUuEbgp8hnUGDw==", "testing."),
            ("arReP9DJtEVyV2Dg3dDp4c/PSk1O6lxkoJ8HcFupoRorBZG+7+1fDAwT1olNddFnQMjmkb8vxwmNMoTAT/BFjQ==", "testing.\n"),
            ("WtaBXIoGC54+vH0NH0CHHE+dRDOsMc/6BrfFu2lEqcKL9+uDuWaf+Xj9mrbQCjjZcpQuX733zyok/jsnqe/Ftw==", "01234567890123456789012345678901234567890123456789012"),
        ];

        let key = key();
        let (pkcse, pkcsd) = (
            PKCS1Encrypt::new(key.public_key().clone(), DefaultRand::default()).unwrap(),
            PKCS1Decrypt::new(key, DefaultRand::default()).unwrap(),
        );

        let (mut encrypt, mut decrypt) = (
            PKCS1EncryptStream::new(pkcse),
            PKCS1DecryptSteam::new(pkcsd),
        );

        for (i, (cipher, msg)) in cases.into_iter().enumerate() {
            let (mut buf1, mut buf2) = (vec![], vec![]);
            let mut cipher = cipher.as_bytes();
            let _len = encode::base::Base64::new(true)
                .decode(&mut cipher, &mut buf1)
                .unwrap();
            let cipher = buf1.clone();
            let mut msg_data = msg.as_bytes();
            buf1.clear();
            let finish = encrypt.stream_encrypt(&mut msg_data, &mut buf1).unwrap();
            let elen = finish.finish(&mut buf1).unwrap();

            assert_eq!(elen.0, msg.len(), "case {i} read data length not match");
            assert_eq!(elen.1, cipher.len(), "case {i} write data length not match");

            let mut cipher_data = buf1.as_slice();
            let finish = decrypt.stream_decrypt(&mut cipher_data, &mut buf2).unwrap();
            let dlen = finish.finish(&mut buf2).unwrap();
            assert_eq!(dlen.0, cipher.len(), "case {i} read data length not match");
            assert_eq!(dlen.1, msg.len(), "case {i} write data length not match");
            assert_eq!(buf2, msg.as_bytes(), "case {i} failed");

            buf2.clear();
            let mut cipher_data = cipher.as_slice();
            let finish = decrypt.stream_decrypt(&mut cipher_data, &mut buf2).unwrap();
            let _dlen = finish.finish(&mut buf2).unwrap();
            assert_eq!(buf2, msg.as_bytes(), "case {i} failed");
        }
    }
}
