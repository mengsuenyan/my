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

use cipher::block_cipher::AES256;
use cipher::cipher_mode::AES256Ofb;
use cipher::stream_cipher::StreamCipherX;
use cipher::BlockCipher;
use crypto_hash::cshake::CSHAKE256;
use crypto_hash::{DigestX, HasherBuilder, HasherType, XOF};
use std::io::Write;
use zeroize::Zeroize;

pub struct SkyEncryptPara {
    hash_name: String,
    block_cipher_name: String,
    cipher_name: String,
    key: String,
}

pub struct SkyEncrypt {
    digest: Box<dyn DigestX>,
    cipher: Box<dyn StreamCipherX>,
    hash_name: String,
    cipher_name: String,
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

    fn aes256_ofb(master_key: &[u8]) -> Result<AES256Ofb, String> {
        let mut cshake = CSHAKE256::new(
            AES256::KEY_SIZE,
            "aes256/ofb".as_bytes(),
            "sky/key".as_bytes(),
        )
        .map_err(|e| format!("{e}"))?;
        cshake.write_all(master_key).map_err(|e| format!("{e}"))?;
        let mut key = cshake.finalize();
        let block_cipher = AES256::new(key.as_slice().try_into().map_err(|e| format!("{e}"))?);
        key.zeroize();

        let mut cshake = CSHAKE256::new(
            AES256::BLOCK_SIZE,
            "aes256/ofb".as_bytes(),
            "sky/iv".as_bytes(),
        )
        .map_err(|e| format!("{e}"))?;
        cshake.write_all(master_key).map_err(|e| format!("{e}"))?;
        let mut iv = cshake.finalize();
        let cipher = AES256Ofb::new(
            block_cipher,
            iv.as_slice().try_into().map_err(|e| format!("{e}"))?,
        );
        iv.zeroize();

        Ok(cipher)
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

        let cipher: Box<dyn StreamCipherX> = match self.cipher_name.as_str() {
            "aes256/ofb" => Box::new(Self::aes256_ofb(master_key.as_slice())?),
            _ => {
                return Err(format!(
                    "do not support the cipher function: `{}`",
                    self.cipher_name
                ))
            }
        };

        self.hash_name.push(' ');
        Ok(SkyEncrypt {
            digest: hash,
            cipher,
            hash_name: self.hash_name,
            cipher_name: self.cipher_name,
        })
    }
}

struct SkyEncryptHeader {
    flag: [u8; 6],
    hash_name_len: u16,
    cipher_name_len: u16,
    hash_len: u32,
    file_len: u32,
    hash_name: Vec<u8>,
    cipher_name: Vec<u8>,
    digest: Vec<u8>,
}

impl From<&SkyEncrypt> for SkyEncryptHeader {
    fn from(value: &SkyEncrypt) -> Self {
        Self {
            flag: Self::start_flag(),
            hash_name_len: value.hash_name.as_bytes().len() as u16,
            cipher_name_len: value.cipher_name.as_bytes().len() as u16,
            hash_len: 0,
            file_len: 0,
            hash_name: value.hash_name.as_bytes().to_vec(),
            cipher_name: value.cipher_name.as_bytes().to_vec(),
            digest: vec![],
        }
    }
}

impl TryFrom<&[u8]> for SkyEncryptHeader {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sl = Self::start_flag().len();
        let min_len = Self::min_len();
        anyhow::ensure!(
            value.len() > min_len,
            "Sky encrypt data as least {} bytes",
            min_len
        );
        anyhow::ensure!(
            Self::start_flag()
                .into_iter()
                .zip(value.iter())
                .all(|(a, &b)| a == b),
            "Sky encrypt data invalid header"
        );
        let hash_name_len = u16::from_be_bytes([value[sl], value[sl + 1]]) as usize;
        let cipher_name_len = u16::from_be_bytes([value[sl + 2], value[sl + 3]]) as usize;
        let hash_len =
            u32::from_be_bytes([value[sl + 4], value[sl + 5], value[sl + 6], value[sl + 7]])
                as usize;
        let file_len =
            u32::from_be_bytes([value[sl + 8], value[sl + 9], value[sl + 10], value[sl + 11]])
                as usize;
        let tmp = min_len + hash_name_len + cipher_name_len + hash_len + file_len;
        anyhow::ensure!(
            value.len() >= tmp,
            "Sky encrypt data need to at least {} bytes, but the real is {} bytes",
            tmp,
            value.len()
        );

        Ok(Self {
            flag: Self::start_flag(),
            hash_name_len: hash_name_len as u16,
            cipher_name_len: cipher_name_len as u16,
            hash_len: hash_len as u32,
            file_len: file_len as u32,
            hash_name: value[min_len..(min_len + hash_name_len)].to_vec(),
            cipher_name: value
                [(min_len + hash_name_len)..(min_len + hash_name_len + cipher_name_len)]
                .to_vec(),
            digest: value[(min_len + hash_name_len + cipher_name_len)
                ..(min_len + hash_name_len + cipher_name_len + hash_len)]
                .to_vec(),
        })
    }
}

impl SkyEncryptHeader {
    const fn min_len() -> usize {
        6 + 2 + 2 + 4 + 4
    }

    const fn start_flag() -> [u8; 6] {
        [0x1, 0x2, 0x53, 0x6b, 0x79, 0x03]
    }

    fn file_offset(&self) -> usize {
        Self::min_len()
            + self.hash_name_len as usize
            + self.cipher_name_len as usize
            + self.hash_len as usize
    }

    fn set_digest(&mut self, h: Vec<u8>) {
        self.hash_len = h.len() as u32;
        self.digest = h;
    }

    fn set_data_size(&mut self, s: usize) {
        self.file_len = s as u32;
    }

    fn into_vec(self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1024);
        v.extend(self.flag);
        v.extend(self.hash_name_len.to_be_bytes());
        v.extend(self.cipher_name_len.to_be_bytes());
        v.extend(self.hash_len.to_be_bytes());
        v.extend(self.file_len.to_be_bytes());
        v.extend(self.hash_name);
        v.extend(self.cipher_name);
        v.extend(self.digest);
        v
    }
}

impl SkyEncrypt {
    pub fn crypt(&mut self, in_data: &[u8], is_decrypt: bool) -> anyhow::Result<Vec<u8>> {
        if is_decrypt {
            self.decrypt(in_data)
        } else {
            self.encrypt(in_data)
        }
    }

    pub fn encrypt(&mut self, in_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut header = SkyEncryptHeader::from(&*self);
        header.set_data_size(in_data.len());

        self.digest.reset_x();
        self.digest.write_all(in_data)?;
        let h = self.digest.finish_x();
        header.set_digest(h);

        let mut data = header.into_vec();

        let _x = self.cipher.stream_encrypt_x(in_data, &mut data)?;
        let _x = self.cipher.stream_encrypt_finish_x(&mut data)?;

        Ok(data)
    }

    pub fn decrypt(&mut self, in_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let header = SkyEncryptHeader::try_from(in_data)?;
        let cipher_data = &in_data[header.file_offset()..];

        let mut data = Vec::with_capacity(1024);
        let _x = self.cipher.stream_decrypt_x(cipher_data, &mut data)?;
        let _x = self.cipher.stream_decrypt_finish_x(&mut data)?;

        anyhow::ensure!(
            data.len() == header.file_len as usize,
            "decrypt data len `{}` not equal to original file len `{}`",
            data.len(),
            header.file_len
        );

        self.digest.reset_x();
        self.digest.write_all(data.as_slice())?;
        let h = self.digest.finish_x();

        anyhow::ensure!(
            h == header.digest,
            "the decrypt data hash not equal to original file hash"
        );

        Ok(data)
    }
}
