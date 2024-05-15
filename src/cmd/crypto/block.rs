use cipher::{
    block_cipher::{AES128, AES192, AES256, SM4},
    BlockCipher, BlockCipherX, BlockEncryptX, DefaultRand, Rand,
};
use clap::{builder::EnumValueParser, Args, ValueEnum};
use std::thread;

use crate::cmd::args::Salt;
use crate::cmd::crypto::header::Header;
use crate::cmd::info::Info;
use crate::cmd::{args::Key, config::MyConfig, kdf::KDFSubArgs};
use crate::log_error;

use super::CryptoCommonArgs;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Debug)]
pub enum BlockCipherType {
    #[value(name = "sm4")]
    SM4,
    #[value(name = "aes128")]
    AES128,
    #[value(name = "aes192")]
    AES192,
    #[value(name = "aes256")]
    AES256,
}

#[derive(Args, Clone)]
#[command(defer(KDFSubArgs::for_crypto_args))]
#[command(about = "block cipher")]
pub struct BlockCryptoArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[arg(name="type", short, long, default_value = "aes128", value_parser = EnumValueParser::<BlockCipherType>::new())]
    pub r#type: BlockCipherType,

    #[arg(
        long,
        help = r#"pad data with `rand | u64(len(data))`
where `len(data) + len(rand) + 8 % block_size = 0 && len(rand) >= block_size - 8`"#
    )]
    pub pad: bool,

    #[command(subcommand)]
    pub kdf: KDFSubArgs,
}

impl BlockCipherType {
    pub fn sm4(self, key: Key) -> anyhow::Result<SM4> {
        Ok(SM4::new(key.try_into()?))
    }

    pub fn aes128(self, key: Key) -> anyhow::Result<AES128> {
        Ok(AES128::new(key.try_into()?))
    }

    pub fn aes192(self, key: Key) -> anyhow::Result<AES192> {
        Ok(AES192::new(key.try_into()?))
    }

    pub fn aes256(self, key: Key) -> anyhow::Result<AES256> {
        Ok(AES256::new(key.try_into()?))
    }

    pub fn block_cipher(
        self,
        key: Key,
    ) -> anyhow::Result<Box<dyn BlockCipherX + Send + Sync + 'static>> {
        Ok(match self {
            BlockCipherType::SM4 => Box::new(self.sm4(key)?),
            BlockCipherType::AES128 => Box::new(self.aes128(key)?),
            BlockCipherType::AES192 => Box::new(self.aes192(key)?),
            BlockCipherType::AES256 => Box::new(self.aes256(key)?),
        })
    }

    pub const fn key_size(self) -> usize {
        match self {
            BlockCipherType::SM4 => SM4::KEY_SIZE,
            BlockCipherType::AES128 => AES128::KEY_SIZE,
            BlockCipherType::AES192 => AES192::KEY_SIZE,
            BlockCipherType::AES256 => AES256::KEY_SIZE,
        }
    }

    pub const fn block_size(self) -> usize {
        match self {
            BlockCipherType::SM4 => SM4::BLOCK_SIZE,
            BlockCipherType::AES128 => AES128::BLOCK_SIZE,
            BlockCipherType::AES192 => AES192::BLOCK_SIZE,
            BlockCipherType::AES256 => AES256::BLOCK_SIZE,
        }
    }
}

impl BlockCryptoArgs {
    /// `is_pad`: data | rand  | u64(len(data)).to_be_bytes(), len(rand) >= block_size - 8, len(data) + len(rand) + 8 % block_size == 0
    pub fn run(
        cipher: Box<dyn BlockCipherX + Sync + Send + 'static>,
        data: &[u8],
        is_decrypt: bool,
        is_pad: bool,
    ) -> anyhow::Result<Vec<u8>> {
        let (mut res, block_size, data_len) = (
            MyConfig::tmp_buf(),
            BlockEncryptX::block_size_x(&cipher),
            data.len(),
        );
        anyhow::ensure!(block_size > 8, "block size must great than 8");

        if is_pad {
            if is_decrypt {
                anyhow::ensure!(data_len >= block_size, "padded encrypted data length need to great than or equal to 9 bytes/block size");
                anyhow::ensure!(
                    data_len % block_size == 0,
                    "data length must be multiple of block size"
                );

                for block in data.chunks_exact(block_size) {
                    cipher.decrypt_block_x(block, &mut res)?;
                }
                let mut l = [0u8; 8];
                l.copy_from_slice(&res[(res.len() - 8)..]);
                let l = u64::from_be_bytes(l) as usize;

                anyhow::ensure!(
                    res.len() >= l + block_size,
                    "invalid padded encrypted data length"
                );
                anyhow::ensure!(
                    res[l..(res.len() - 8)].iter().all(|&x| x != 0),
                    "invalid padded encrypted data format"
                );
                res.truncate(l);
            } else {
                let mut itr = data.chunks_exact(block_size);
                for block in itr.by_ref() {
                    cipher.encrypt_block_x(block, &mut res)?;
                }
                let mut data = itr.remainder().to_vec();
                let l = block_size - 8 + (block_size - data.len() % block_size) % block_size;
                data.resize(itr.remainder().len() + l, 0);
                let mut rnd = DefaultRand::default();
                let rand = &mut data[itr.remainder().len()..];
                rnd.rand(rand);
                'outer: while rand.iter().any(|&x| x == 0) {
                    let mut tmp = [0u8; 4];
                    rnd.rand(&mut tmp);
                    for x in tmp {
                        if x != 0 {
                            if let Some(y) = rand.iter_mut().find(|x| **x == 0) {
                                *y = x;
                            } else {
                                break 'outer;
                            }
                        }
                    }
                }

                data.extend((data_len as u64).to_be_bytes());
                for block in data.chunks(block_size) {
                    cipher.encrypt_block_x(block, &mut res)?;
                }
            }
        } else {
            anyhow::ensure!(
                data_len % block_size == 0,
                "data length must be multiple of block size"
            );
            for block in data.chunks_exact(block_size) {
                if is_decrypt {
                    cipher.decrypt_block_x(block, &mut res)?;
                } else {
                    cipher.encrypt_block_x(block, &mut res)?;
                }
            }
        }

        Ok(res)
    }

    pub fn generate_key(
        mut kdf: KDFSubArgs,
        header: &Header,
        block_type: BlockCipherType,
    ) -> anyhow::Result<Key> {
        kdf.append_salt(Salt::from(header.file_name()))?;
        kdf.append_salt(Salt::from(header.digest()))?;

        kdf.set_ksize(block_type.key_size());
        kdf.run()
    }

    fn cipher_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let Some((data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let key = Self::generate_key(self.kdf.clone(), &header, self.r#type)?;
        let cipher = self.r#type.block_cipher(key)?;

        let data = Self::run(cipher, data, self.common.decrypt, self.pad)?;

        if !self.common.decrypt {
            header.set_info(self.r#type.merge_name(&self.kdf));
        }

        self.common.write_data(header, &data, &self.common.io)?;

        Ok(())
    }

    pub fn exe(mut self, pipe: Option<&[u8]>) {
        self.common.assert_only_one_datasource(pipe).unwrap();
        self.kdf.prompt_input_password().unwrap();

        if let Some(pipe) = pipe {
            self.cipher_data(pipe).unwrap();
            return;
        }

        if let Some(msg) = self.common.msg.as_deref() {
            self.cipher_data(msg.as_bytes()).unwrap();
            return;
        }

        let (ios, cpus, header_info) = (
            self.common.io.clone().decompose().unwrap(),
            MyConfig::config().threads,
            self.r#type.merge_name(&self.kdf),
        );

        if ios.is_empty() {
            return;
        }

        let (common, kdf, block_type, is_pad, header_info) = (
            &self.common,
            &self.kdf,
            self.r#type,
            self.pad,
            header_info.as_str(),
        );

        thread::scope(|s| {
            for chunk in ios.chunks(ios.len().div_ceil(cpus)) {
                s.spawn(move || {
                    for io_arg in chunk {
                        let Some((data, mut header)) =
                            log_error(common.read_from_ioargs(io_arg)).flatten()
                        else {
                            continue;
                        };

                        if !common.decrypt {
                            header.set_info(header_info.to_string());
                        }

                        let Some(key) =
                            log_error(Self::generate_key(kdf.clone(), &header, block_type))
                        else {
                            continue;
                        };

                        let Some(cipher) = log_error(block_type.block_cipher(key)) else {
                            continue;
                        };

                        let Some(data) =
                            log_error(Self::run(cipher, &data, common.decrypt, is_pad))
                        else {
                            continue;
                        };

                        log_error(common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}
