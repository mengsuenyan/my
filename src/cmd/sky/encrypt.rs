//!
//! 起始头: 6字节
//! 0x01 | 0x02 | 0x53 | 0x6b | 0x79 | 0x03
//! 加密组件标识:
//! 哈希函数: 4字节;
//! 加密函数: 4字节;
//! 密钥初始化向量派生类型: 4字节;
//! 文件偏移地址: 4字节;
//! 文件名
//! 文件内容
//!

use super::{SkyEncryptHeader, SkyVer};
use cipher::block_cipher::AES256;
use cipher::cipher_mode::AES256Ofb;
use cipher::stream_cipher::StreamCipherX;
use cipher::{BlockCipher, CipherError};
use crypto_hash::cshake::CSHAKE256;
use crypto_hash::{DigestX, HasherBuilder, HasherType, XOF};
use num_bigint::BigUint;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

pub struct SkyEncryptPara {
    hash_name: String,
    block_cipher_name: String,
    cipher_name: String,
    key: String,
}

#[allow(clippy::type_complexity)]
pub struct SkyEncrypt {
    pub(super) version: SkyVer,
    pub(super) digest: Box<dyn DigestX>,
    pub(super) cipher: Box<dyn StreamCipherX>,
    pub(super) hash_name: String,
    pub(super) cipher_name: String,
    pub(super) key: Vec<u8>,
    pub(super) iv_cshake: CSHAKE256,
    pub(super) update_iv: Option<Box<dyn Fn(Vec<u8>) -> Result<(), CipherError>>>,
}

impl Default for SkyEncryptPara {
    fn default() -> Self {
        Self::new()
    }
}

impl SkyEncryptPara {
    pub fn new() -> Self {
        Self {
            hash_name: String::default(),
            block_cipher_name: String::default(),
            cipher_name: String::default(),
            key: String::default(),
        }
    }

    pub fn hash_name(mut self, name: &str) -> Self {
        self.hash_name = name.to_lowercase();
        self
    }

    pub fn block_cipher_name(mut self, name: &str) -> Self {
        self.block_cipher_name = name.to_lowercase();
        self
    }

    pub fn cipher_name(mut self, name: &str) -> Self {
        self.cipher_name = name.to_lowercase();
        self
    }

    pub fn password(mut self, key: &str) -> Self {
        self.key = key.to_string();
        self
    }

    #[allow(clippy::type_complexity)]
    fn aes256_ofb(
        master_key: &[u8],
    ) -> Result<
        (
            CSHAKE256,
            Box<dyn StreamCipherX>,
            Box<dyn Fn(Vec<u8>) -> Result<(), CipherError>>,
        ),
        String,
    > {
        let mut cshake = CSHAKE256::new(
            AES256::KEY_SIZE,
            "aes256/ofb".as_bytes(),
            "sky/key".as_bytes(),
        )
        .map_err(|e| format!("{e}"))?;
        let (mut aes_key, mut cnt, bound) = (
            BigUint::from_bytes_le(master_key),
            master_key.len() as u64,
            1000 * 8,
        );
        while aes_key.bits() < bound {
            aes_key *= cnt.pow(2);
            cnt += (aes_key.bits() + 7) >> 3;
        }
        let mut aes_key = aes_key.to_bytes_be();
        aes_key.truncate((bound >> 3) as usize);
        cshake.write_all(&aes_key).map_err(|e| format!("{e}"))?;
        let mut key = cshake.finalize();
        let block_cipher = AES256::new(key.as_slice().try_into().map_err(|e| format!("{e}"))?);
        key.zeroize();

        let mut iv_cshake = CSHAKE256::new(
            AES256::BLOCK_SIZE,
            "aes256/ofb".as_bytes(),
            "sky/iv".as_bytes(),
        )
        .map_err(|e| format!("{e}"))?;
        iv_cshake
            .write_all(master_key)
            .map_err(|e| format!("{e}"))?;
        let iv = iv_cshake.finalize();
        let cipher = AES256Ofb::new(block_cipher, iv).map_err(|e| format!("{e}"))?;

        let ofb = Arc::new(Mutex::new(cipher));
        let x = ofb.clone();
        let f = move |iv: Vec<u8>| match x.lock() {
            Ok(mut x) => x.set_iv(iv),
            Err(e) => Err(CipherError::Other(format!(
                "AES256Ofb set_iv failed due to: {e}"
            ))),
        };

        Ok((iv_cshake, Box::new(ofb), Box::new(f)))
    }

    pub fn build(mut self) -> Result<SkyEncrypt, String> {
        let hash = match self.hash_name.as_str() {
            "sha2-256" => HasherBuilder::new(HasherType::SHA2_256)
                .build()
                .map_err(|e| format!("{e}")),
            "sha3-256" => HasherBuilder::new(HasherType::SHA3_256)
                .build()
                .map_err(|e| format!("{e}")),
            _ => Err(format!(
                "do not support the hash function: `{}`",
                self.hash_name
            )),
        }?;

        let master_key = self.key.as_bytes().to_vec();
        self.key.zeroize();

        #[allow(clippy::type_complexity)]
        let (iv_cshake, cipher, update_iv): (
            CSHAKE256,
            Box<dyn StreamCipherX>,
            Option<Box<dyn Fn(Vec<u8>) -> Result<(), CipherError>>>,
        ) = match self.cipher_name.as_str() {
            "aes256/ofb" => {
                let (x, y, z) = Self::aes256_ofb(master_key.as_slice())?;
                (x, y, Some(z))
            }
            _ => {
                return Err(format!(
                    "do not support the cipher function: `{}`",
                    self.cipher_name
                ))
            }
        };

        Ok(SkyEncrypt {
            version: SkyVer::V1,
            digest: hash,
            cipher,
            hash_name: self.hash_name,
            cipher_name: self.cipher_name,
            iv_cshake,
            key: master_key,
            update_iv,
        })
    }
}

impl SkyEncrypt {
    pub fn crypt(
        &mut self,
        in_data: &[u8],
        filename: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        if is_decrypt {
            self.decrypt(in_data)
        } else {
            self.encrypt(in_data, filename)
        }
    }

    pub fn encrypt(&mut self, in_data: &[u8], filename: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.version {
            SkyVer::V1 => self.encrypt_v1(in_data, filename),
        }
    }

    pub fn decrypt(&mut self, in_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.version {
            SkyVer::V1 => self.decrypt_v1(in_data),
        }
    }

    /// 检查`encrypted_data`是不是由`data`加密得到的
    pub fn is_encrypted_data_by_the_data(&mut self, encrypted_data: &[u8], data: &[u8]) -> bool {
        if let Ok(header) = SkyEncryptHeader::only_parse_header_from_b64(encrypted_data) {
            let Ok(ver) = SkyVer::try_from(header.version()) else {
                return false;
            };

            let Ok(h1) = (match ver {
                SkyVer::V1 => self.decrypt_digest_v1(&header),
            }) else {
                return false;
            };

            let h2 = self.digest.digest(data);
            if h1 == h2 {
                return true;
            }
        }

        false
    }

    pub fn detect_encrypted_info(p: &Path) -> anyhow::Result<String> {
        let content = std::fs::read(p).map_err(|e| {
            anyhow::Error::msg(format!(
                "cannot detect the `{}` meta info, due to {}",
                p.display(),
                e
            ))
        })?;

        let header = SkyEncryptHeader::only_parse_header_from_b64(&content).map_err(|e| {
            anyhow::Error::msg(format!("cannot parse the encrypted data, due to {}", e))
        })?;

        let (hash, cipher, file) = (
            String::from_utf8_lossy(&header.hash_name),
            String::from_utf8_lossy(&header.cipher_name),
            String::from_utf8_lossy(&header.file_name),
        );

        Ok(format!(
            "{{ver: {}, hash: {}, cipher: {}, file: {}}}",
            header.version(),
            hash,
            cipher,
            file
        ))
    }
}
