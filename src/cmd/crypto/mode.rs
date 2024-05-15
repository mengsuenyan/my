use std::ops::Range;
use std::thread;

use cipher::cipher_mode::{CBCCs, CBCCsMode, DefaultCounter, CBC, CFB, CTR, OFB};
use cipher::stream_cipher::StreamDecryptX;
use cipher::{
    cipher_mode::{DefaultPadding, ECB},
    stream_cipher::StreamCipherX,
};
use clap::{builder::EnumValueParser, Args, ValueEnum};

use crate::cmd::args::{IVector, Salt};
use crate::cmd::crypto::header::Header;
use crate::cmd::info::Info;
use crate::cmd::{
    args::{IVArgs, Key},
    config::MyConfig,
    kdf::KDFSubArgs,
};
use crate::log_error;

use super::{block::BlockCipherType, CryptoCommonArgs};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Padding {
    #[value(name = "0x80", help = "append 0x80, then padding 0x00 to block size")]
    HEX80,
}

#[derive(Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum Counter {
    #[value(name = "inc", help = "increment counter")]
    Inc,
}

#[derive(Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum CBCCSType {
    #[value(name = "cs1")]
    CBCCS1,
    #[value(name = "cs2")]
    CBCCS2,
    #[value(name = "cs3")]
    CBCCS3,
}

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args))]
#[command(about = "The Electronic Codebook Mode(NIST SP 800-38A)")]
pub struct ECBArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[arg(name="type", short, long, default_value = "aes128", value_parser = EnumValueParser::<BlockCipherType>::new())]
    pub r#type: BlockCipherType,

    /// append 0x80, then padding 0x00 to block size
    #[arg(value_enum, long, default_value = "0x80")]
    pub pad: Padding,

    #[command(subcommand)]
    pub kdf: KDFSubArgs,
}

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args), mut_group("iv", |g| g.required(false)))]
#[command(about = "The Cipher Block Chaining Mode(NIST SP 800-38A)")]
pub struct CBCArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[arg(name="type", short, long, default_value = "aes128", value_parser = EnumValueParser::<BlockCipherType>::new())]
    pub r#type: BlockCipherType,

    /// append 0x80, then padding 0x00 to block size
    #[arg(value_enum, long, default_value = "0x80")]
    pub pad: Padding,

    #[command(subcommand)]
    pub kdf: KDFSubArgs,

    #[command(flatten)]
    iv: IVArgs,
}

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args), mut_group("iv", |g| g.required(false)))]
#[command(about = "The Cipher Feedback Mode(NIST SP 800-38A)")]
pub struct CFBArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[arg(name="type", short, long, default_value = "aes128", value_parser = EnumValueParser::<BlockCipherType>::new())]
    pub r#type: BlockCipherType,

    /// append 0x80, then padding 0x00 to block size
    #[arg(value_enum, long, default_value = "0x80")]
    pub pad: Padding,

    #[command(subcommand)]
    pub kdf: KDFSubArgs,

    #[command(flatten)]
    iv: IVArgs,

    #[arg(
        short,
        help = "the CFB `s` parameter that need to less than or equal to block size"
    )]
    #[arg(value_parser = clap::value_parser!(u32).range(1..), default_value = "16")]
    s: u32,
}

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args), mut_group("iv", |g| g.required(false)))]
#[command(about = "The Output Feedback Mode(NIST SP 800-38A)")]
pub struct OFBArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[arg(name="type", short, long, default_value = "aes128", value_parser = EnumValueParser::<BlockCipherType>::new())]
    pub r#type: BlockCipherType,

    #[command(subcommand)]
    pub kdf: KDFSubArgs,

    #[command(flatten)]
    iv: IVArgs,
}

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args), mut_group("iv", |g| g.required(false)))]
#[command(about = "The Counter Mode(NIST SP 800-38A)")]
pub struct CTRArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[arg(name="type", short, long, default_value = "aes128", value_parser = EnumValueParser::<BlockCipherType>::new())]
    pub r#type: BlockCipherType,

    #[arg(value_enum, long, default_value = "inc", help = "counter type")]
    pub ctr: Counter,

    #[command(subcommand)]
    pub kdf: KDFSubArgs,

    #[command(flatten)]
    iv: IVArgs,
}

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args), mut_group("iv", |g| g.required(false)))]
#[command(about = "The Cipher Block Chaining-Ciphertext Stealing(NIST SP 800-38A-add)")]
pub struct CBCCSArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[arg(name="type", short, long, default_value = "aes128", value_parser = EnumValueParser::<BlockCipherType>::new())]
    pub r#type: BlockCipherType,

    #[arg(
        value_enum,
        long,
        default_value = "cs1",
        help = "ciphertext stealing type"
    )]
    pub cs: CBCCSType,

    #[command(subcommand)]
    pub kdf: KDFSubArgs,

    #[command(flatten)]
    iv: IVArgs,
}

impl ECBArgs {
    pub fn ecb_cipher(
        block: BlockCipherType,
        pad: Padding,
        key: Key,
    ) -> anyhow::Result<Box<dyn StreamCipherX + Send + Sync + 'static>> {
        let block_cipher = block.block_cipher(key)?;
        match pad {
            Padding::HEX80 => Ok(Box::new(ECB::<DefaultPadding, _>::new(block_cipher))),
        }
    }

    pub fn run(
        mut cipher: Box<dyn StreamCipherX + Send + Sync + 'static>,
        data: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        let mut res = MyConfig::tmp_buf();
        if is_decrypt {
            let _ = cipher.stream_decrypt_x(data, &mut res)?;
            let _ = cipher.stream_decrypt_finish_x(&mut res)?;
        } else {
            let _ = cipher.stream_encrypt_x(data, &mut res)?;
            let _ = cipher.stream_encrypt_finish_x(&mut res)?;
        }

        Ok(res)
    }

    pub fn generate_key(
        mut kdf: KDFSubArgs,
        header: &Header,
        block_type: BlockCipherType,
    ) -> anyhow::Result<Key> {
        kdf.append_key(Key::from(header.digest()))?;
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

        let cipher = Self::ecb_cipher(self.r#type, self.pad, key)?;
        let data = Self::run(cipher, data, self.common.decrypt)?;

        if !self.common.decrypt {
            header.set_info(self.merge_name(&self.r#type.merge_name(&self.kdf)));
        }

        self.common.write_data(header, &data, &self.common.io)?;

        Ok(())
    }

    pub fn exe(mut self, pipe: Option<&[u8]>) {
        self.kdf.prompt_input_password().unwrap();
        self.common.assert_only_one_datasource(pipe).unwrap();

        if let Some(pipe) = pipe {
            self.cipher_data(pipe).unwrap();
            return;
        }

        if let Some(msg) = self.common.msg.as_deref() {
            self.cipher_data(msg.as_bytes()).unwrap();
            return;
        }

        self.multiple_thread_to_run();
    }

    fn multiple_thread_to_run(&self) {
        let (ios, cpus, header_info) = (
            self.common.io.clone().decompose().unwrap(),
            MyConfig::config().threads,
            self.merge_name(&self.r#type.merge_name(&self.kdf)),
        );

        if ios.is_empty() {
            return;
        }

        let (common, kdf, block_type, pad, header_info) = (
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

                        let Some(cipher) = log_error(Self::ecb_cipher(block_type, pad, key)) else {
                            continue;
                        };

                        let Some(data) = log_error(Self::run(cipher, &data, common.decrypt)) else {
                            continue;
                        };

                        log_error(common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}

impl CBCArgs {
    pub fn cbc_cipher(
        block: BlockCipherType,
        pad: Padding,
        key: Key,
        iv: IVector,
    ) -> anyhow::Result<Box<dyn StreamCipherX + Send + Sync + 'static>> {
        let block_cipher = block.block_cipher(key)?;
        match pad {
            Padding::HEX80 => Ok(Box::new(CBC::<DefaultPadding, _>::new(
                block_cipher,
                iv.to_bytes(),
            )?)),
        }
    }

    pub fn run(
        cipher: Box<dyn StreamCipherX + Send + Sync + 'static>,
        data: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        ECBArgs::run(cipher, data, is_decrypt)
    }

    pub fn generate_key(
        mut kdf: KDFSubArgs,
        header: &Header,
        iv_arg: &IVArgs,
        block_type: BlockCipherType,
    ) -> anyhow::Result<(Key, IVector)> {
        kdf.append_key(Key::from(header.digest()))?;
        let mut iv_kdf = kdf.clone();

        kdf.append_salt(Salt::from(header.file_name()))?;
        kdf.append_salt(Salt::from(header.digest()))?;

        if iv_arg.is_specified() {
            let iv: IVector = iv_arg.try_into()?;
            iv_kdf.append_salt(iv)?;
        }
        iv_kdf.append_salt(Salt::from(header.file_name()))?;
        iv_kdf.append_salt(Salt::from(header.digest()))?;

        kdf.set_ksize(block_type.key_size());
        iv_kdf.set_ksize(block_type.block_size());
        Ok((kdf.run()?, iv_kdf.run()?))
    }

    fn cipher_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let Some((data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let (key, iv) = Self::generate_key(self.kdf.clone(), &header, &self.iv, self.r#type)?;
        let cipher = Self::cbc_cipher(self.r#type, self.pad, key, iv)?;
        let data = Self::run(cipher, data, self.common.decrypt)?;

        if !self.common.decrypt {
            header.set_info(self.merge_name(&self.r#type.merge_name(&self.kdf)));
        }

        self.common.write_data(header, &data, &self.common.io)?;

        Ok(())
    }

    pub fn exe(mut self, pipe: Option<&[u8]>) {
        self.kdf.prompt_input_password().unwrap();
        self.common.assert_only_one_datasource(pipe).unwrap();

        if let Some(pipe) = pipe {
            self.cipher_data(pipe).unwrap();
            return;
        }

        if let Some(msg) = self.common.msg.as_deref() {
            self.cipher_data(msg.as_bytes()).unwrap();
            return;
        }

        self.multiple_thread_to_run();
    }

    fn multiple_thread_to_run(&self) {
        let (ios, cpus, header_info) = (
            self.common.io.clone().decompose().unwrap(),
            MyConfig::config().threads,
            self.merge_name(&self.r#type.merge_name(&self.kdf)),
        );

        if ios.is_empty() {
            return;
        }
        let (common, kdf, block_type, pad, iv, header_info) = (
            &self.common,
            &self.kdf,
            self.r#type,
            self.pad,
            &self.iv,
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

                        let Some((key, iv)) =
                            log_error(Self::generate_key(kdf.clone(), &header, iv, block_type))
                        else {
                            continue;
                        };

                        let Some(cipher) = log_error(Self::cbc_cipher(block_type, pad, key, iv))
                        else {
                            continue;
                        };

                        let Some(data) = log_error(Self::run(cipher, &data, common.decrypt)) else {
                            continue;
                        };

                        log_error(common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}

impl CFBArgs {
    pub fn cfb_cipher(
        block: BlockCipherType,
        pad: Padding,
        key: Key,
        iv: IVector,
        s: usize,
    ) -> anyhow::Result<Box<dyn StreamCipherX + Send + Sync + 'static>> {
        let block_cipher = block.block_cipher(key)?;
        match pad {
            Padding::HEX80 => Ok(Box::new(CFB::<DefaultPadding, _>::new(
                block_cipher,
                iv.to_bytes(),
                s,
            )?)),
        }
    }

    pub fn run(
        cipher: Box<dyn StreamCipherX + Send + Sync + 'static>,
        data: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        ECBArgs::run(cipher, data, is_decrypt)
    }

    pub fn generate_key(
        mut kdf: KDFSubArgs,
        header: &Header,
        iv_arg: &IVArgs,
        s: u32,
        block_type: BlockCipherType,
    ) -> anyhow::Result<(Key, IVector)> {
        kdf.append_key(Key::from(header.digest()))?;
        let mut iv_kdf = kdf.clone();
        let s = Vec::from(s.to_be_bytes());

        kdf.append_key(Key::from(s.as_slice()))?;
        kdf.append_salt(Salt::from(header.file_name()))?;
        kdf.append_salt(Salt::from(header.digest()))?;

        if iv_arg.is_specified() {
            let iv: IVector = iv_arg.try_into()?;
            iv_kdf.append_salt(iv)?;
        }
        iv_kdf.append_salt(Salt::from(header.file_name()))?;
        iv_kdf.append_salt(Salt::from(header.digest()))?;
        iv_kdf.append_salt(Salt::from(s))?;

        kdf.set_ksize(block_type.key_size());
        iv_kdf.set_ksize(block_type.block_size());
        Ok((kdf.run()?, iv_kdf.run()?))
    }

    fn cipher_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let Some((data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let (key, iv) =
            Self::generate_key(self.kdf.clone(), &header, &self.iv, self.s, self.r#type)?;
        let cipher = Self::cfb_cipher(self.r#type, self.pad, key, iv, self.s as usize)?;
        let data = Self::run(cipher, data, self.common.decrypt)?;

        if !self.common.decrypt {
            header.set_info(self.merge_name(&self.r#type.merge_name(&self.kdf)));
        }

        self.common.write_data(header, &data, &self.common.io)?;

        Ok(())
    }

    pub fn exe(mut self, pipe: Option<&[u8]>) {
        assert!(
            self.s as usize <= self.r#type.block_size(),
            "`s` must be less than block size `{}`",
            self.r#type.block_size()
        );
        self.kdf.prompt_input_password().unwrap();
        self.common.assert_only_one_datasource(pipe).unwrap();

        if let Some(pipe) = pipe {
            self.cipher_data(pipe).unwrap();
            return;
        }

        if let Some(msg) = self.common.msg.as_deref() {
            self.cipher_data(msg.as_bytes()).unwrap();
            return;
        }

        self.multiple_thread_to_run();
    }

    fn multiple_thread_to_run(&self) {
        let (ios, cpus, header_info) = (
            self.common.io.clone().decompose().unwrap(),
            MyConfig::config().threads,
            self.merge_name(&self.r#type.merge_name(&self.kdf)),
        );

        if ios.is_empty() {
            return;
        }
        let (common, kdf, s, block_type, pad, iv, header_info) = (
            &self.common,
            &self.kdf,
            self.s,
            self.r#type,
            self.pad,
            &self.iv,
            header_info.as_str(),
        );

        thread::scope(|scope| {
            for chunk in ios.chunks(ios.len().div_ceil(cpus)) {
                scope.spawn(move || {
                    for io_arg in chunk {
                        let Some((data, mut header)) =
                            log_error(common.read_from_ioargs(io_arg)).flatten()
                        else {
                            continue;
                        };

                        if !common.decrypt {
                            header.set_info(header_info.to_string());
                        }

                        let Some((key, iv)) =
                            log_error(Self::generate_key(kdf.clone(), &header, iv, s, block_type))
                        else {
                            continue;
                        };

                        let Some(cipher) =
                            log_error(Self::cfb_cipher(block_type, pad, key, iv, s as usize))
                        else {
                            continue;
                        };

                        let Some(data) = log_error(Self::run(cipher, &data, common.decrypt)) else {
                            continue;
                        };

                        log_error(common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}

impl OFBArgs {
    pub fn ofb_cipher(
        block: BlockCipherType,
        key: Key,
        iv: IVector,
    ) -> anyhow::Result<Box<dyn StreamCipherX + Send + Sync + 'static>> {
        let block_cipher = block.block_cipher(key)?;
        Ok(Box::new(OFB::new(block_cipher, iv.to_bytes())?))
    }

    pub fn run(
        cipher: Box<dyn StreamCipherX + Send + Sync + 'static>,
        data: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        ECBArgs::run(cipher, data, is_decrypt)
    }

    pub fn generate_key(
        mut kdf: KDFSubArgs,
        header: &Header,
        iv_arg: &IVArgs,
        block_type: BlockCipherType,
    ) -> anyhow::Result<(Key, IVector)> {
        kdf.append_key(Key::from(vec![]))?;
        let mut iv_kdf = kdf.clone();

        kdf.append_salt(Salt::from(header.file_name()))?;
        kdf.append_salt(Salt::from(header.digest()))?;

        iv_kdf.append_key(Key::from(header.digest()))?;
        if iv_arg.is_specified() {
            let iv: IVector = iv_arg.try_into()?;
            iv_kdf.append_salt(iv)?;
        }
        iv_kdf.append_salt(Salt::from(header.file_name()))?;
        iv_kdf.append_salt(Salt::from(header.digest()))?;

        kdf.set_ksize(block_type.key_size());
        iv_kdf.set_ksize(block_type.block_size());
        Ok((kdf.run()?, iv_kdf.run()?))
    }

    fn cipher_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let Some((data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let (key, iv) = Self::generate_key(self.kdf.clone(), &header, &self.iv, self.r#type)?;
        let cipher = Self::ofb_cipher(self.r#type, key, iv)?;
        let data = Self::run(cipher, data, self.common.decrypt)?;

        if !self.common.decrypt {
            header.set_info(self.merge_name(&self.r#type.merge_name(&self.kdf)));
        }

        self.common.write_data(header, &data, &self.common.io)?;

        Ok(())
    }

    pub fn exe(mut self, pipe: Option<&[u8]>) {
        self.kdf.prompt_input_password().unwrap();
        self.common.assert_only_one_datasource(pipe).unwrap();

        if let Some(pipe) = pipe {
            self.cipher_data(pipe).unwrap();
            return;
        }

        if let Some(msg) = self.common.msg.as_deref() {
            self.cipher_data(msg.as_bytes()).unwrap();
            return;
        }

        self.multiple_thread_to_run();
    }

    fn multiple_thread_to_run(&self) {
        let (ios, cpus, header_info) = (
            self.common.io.clone().decompose().unwrap(),
            MyConfig::config().threads,
            self.merge_name(&self.r#type.merge_name(&self.kdf)),
        );

        if ios.is_empty() {
            return;
        }
        let (common, kdf, block_type, iv, header_info) = (
            &self.common,
            &self.kdf,
            self.r#type,
            &self.iv,
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

                        let Some((key, iv)) =
                            log_error(Self::generate_key(kdf.clone(), &header, iv, block_type))
                        else {
                            continue;
                        };

                        let Some(cipher) = log_error(Self::ofb_cipher(block_type, key, iv)) else {
                            continue;
                        };

                        let Some(data) = log_error(Self::run(cipher, &data, common.decrypt)) else {
                            continue;
                        };

                        log_error(common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}

impl CTRArgs {
    pub fn ctr_cipher(
        block: BlockCipherType,
        counter: Counter,
        key: Key,
        iv: IVector,
    ) -> anyhow::Result<Box<dyn StreamCipherX + Send + Sync + 'static>> {
        let block_cipher = block.block_cipher(key)?;
        let counter = match counter {
            Counter::Inc => DefaultCounter::new(
                iv.to_bytes(),
                Range {
                    start: 0,
                    end: block.block_size(),
                },
            )?,
        };

        Ok(Box::new(CTR::new(block_cipher, counter)?))
    }

    pub fn run(
        cipher: Box<dyn StreamCipherX + Send + Sync + 'static>,
        data: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        ECBArgs::run(cipher, data, is_decrypt)
    }

    pub fn generate_key(
        mut kdf: KDFSubArgs,
        header: &Header,
        iv_arg: &IVArgs,
        block_type: BlockCipherType,
    ) -> anyhow::Result<(Key, IVector)> {
        kdf.append_salt(Salt::from(header.file_name()))?;
        kdf.append_salt(Salt::from(header.digest()))?;

        let mut iv_kdf = kdf.clone();
        iv_kdf.append_key(Key::from(header.digest()))?;
        if iv_arg.is_specified() {
            let iv: IVector = iv_arg.try_into()?;
            iv_kdf.append_salt(iv)?;
        }
        iv_kdf.append_salt(Salt::from(header.file_name()))?;
        iv_kdf.append_salt(Salt::from(header.digest()))?;

        kdf.set_ksize(block_type.key_size());
        iv_kdf.set_ksize(block_type.block_size());
        Ok((kdf.run()?, iv_kdf.run()?))
    }

    fn cipher_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let Some((data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let (key, iv) = Self::generate_key(self.kdf.clone(), &header, &self.iv, self.r#type)?;
        let cipher = Self::ctr_cipher(self.r#type, self.ctr, key, iv)?;
        let data = Self::run(cipher, data, self.common.decrypt)?;

        if !self.common.decrypt {
            header.set_info(self.merge_name(&self.r#type.merge_name(&self.kdf)));
        }

        self.common.write_data(header, &data, &self.common.io)?;

        Ok(())
    }

    pub fn exe(mut self, pipe: Option<&[u8]>) {
        self.kdf.prompt_input_password().unwrap();
        self.common.assert_only_one_datasource(pipe).unwrap();

        if let Some(pipe) = pipe {
            self.cipher_data(pipe).unwrap();
            return;
        }

        if let Some(msg) = self.common.msg.as_deref() {
            self.cipher_data(msg.as_bytes()).unwrap();
            return;
        }

        self.multiple_thread_to_run();
    }

    fn multiple_thread_to_run(&self) {
        let (ios, cpus, header_info) = (
            self.common.io.clone().decompose().unwrap(),
            MyConfig::config().threads,
            self.merge_name(&self.r#type.merge_name(&self.kdf)),
        );

        if ios.is_empty() {
            return;
        }
        let (common, kdf, counter, block_type, iv, header_info) = (
            &self.common,
            &self.kdf,
            self.ctr,
            self.r#type,
            &self.iv,
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

                        let Some((key, iv)) =
                            log_error(Self::generate_key(kdf.clone(), &header, iv, block_type))
                        else {
                            continue;
                        };

                        let Some(cipher) =
                            log_error(Self::ctr_cipher(block_type, counter, key, iv))
                        else {
                            continue;
                        };

                        let Some(data) = log_error(Self::run(cipher, &data, common.decrypt)) else {
                            continue;
                        };

                        log_error(common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}

impl From<CBCCSType> for CBCCsMode {
    fn from(value: CBCCSType) -> Self {
        match value {
            CBCCSType::CBCCS1 => Self::CbcCs1,
            CBCCSType::CBCCS2 => Self::CbcCs2,
            CBCCSType::CBCCS3 => Self::CbcCs3,
        }
    }
}

impl From<CBCCSType> for String {
    fn from(value: CBCCSType) -> Self {
        match value {
            CBCCSType::CBCCS1 => "cbccs1",
            CBCCSType::CBCCS2 => "cbccs2",
            CBCCSType::CBCCS3 => "cbccs3",
        }
        .to_string()
    }
}

impl CBCCSArgs {
    pub fn cs_cipher(
        block: BlockCipherType,
        cs: CBCCSType,
        key: Key,
        iv: IVector,
    ) -> anyhow::Result<Box<dyn StreamCipherX + Send + Sync + 'static>> {
        let block_cipher = block.block_cipher(key)?;

        Ok(Box::new(CBCCs::new(
            block_cipher,
            iv.to_bytes(),
            cs.into(),
        )?))
    }

    pub fn run(
        cipher: Box<dyn StreamCipherX + Send + Sync + 'static>,
        data: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        ECBArgs::run(cipher, data, is_decrypt)
    }

    pub fn generate_key(
        mut kdf: KDFSubArgs,
        header: &Header,
        iv_arg: &IVArgs,
        cs: CBCCSType,
        block_type: BlockCipherType,
    ) -> anyhow::Result<(Key, IVector)> {
        kdf.append_key(Key::from(header.digest()))?;
        kdf.append_key(Key::from(String::from(cs).into_bytes()))?;
        let mut iv_kdf = kdf.clone();

        kdf.append_salt(Salt::from(header.file_name()))?;
        kdf.append_salt(Salt::from(header.digest()))?;

        if iv_arg.is_specified() {
            let iv: IVector = iv_arg.try_into()?;
            iv_kdf.append_salt(iv)?;
        }
        iv_kdf.append_salt(Salt::from(header.file_name()))?;
        iv_kdf.append_salt(Salt::from(header.digest()))?;

        kdf.set_ksize(block_type.key_size());
        iv_kdf.set_ksize(block_type.block_size());
        Ok((kdf.run()?, iv_kdf.run()?))
    }

    fn cipher_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let Some((data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let (key, iv) =
            Self::generate_key(self.kdf.clone(), &header, &self.iv, self.cs, self.r#type)?;
        let cipher = Self::cs_cipher(self.r#type, self.cs, key, iv)?;
        let data = Self::run(cipher, data, self.common.decrypt)?;

        if !self.common.decrypt {
            header.set_info(self.merge_name(&self.r#type.merge_name(&self.kdf)));
        }

        self.common.write_data(header, &data, &self.common.io)?;

        Ok(())
    }

    pub fn exe(mut self, pipe: Option<&[u8]>) {
        self.kdf.prompt_input_password().unwrap();
        self.common.assert_only_one_datasource(pipe).unwrap();

        if let Some(pipe) = pipe {
            assert!(
                pipe.len() > self.r#type.block_size(),
                "CBC-CS data must great than block size"
            );
            self.cipher_data(pipe).unwrap();
            return;
        }

        if let Some(msg) = self.common.msg.as_deref() {
            assert!(
                msg.as_bytes().len() > self.r#type.block_size(),
                "CBC-CS data must great than block size"
            );
            self.cipher_data(msg.as_bytes()).unwrap();
            return;
        }

        self.multiple_thread_to_run();
    }

    fn multiple_thread_to_run(&self) {
        let (ios, cpus, header_info) = (
            self.common.io.clone().decompose().unwrap(),
            MyConfig::config().threads,
            self.merge_name(&self.r#type.merge_name(&self.kdf)),
        );

        if ios.is_empty() {
            return;
        }
        let (common, kdf, cs, block_type, iv, header_info) = (
            &self.common,
            &self.kdf,
            self.cs,
            self.r#type,
            &self.iv,
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

                        if data.len() <= block_type.block_size() {
                            log::error!("the data length must great than the block size `{}` when using the CBC-CS mode", block_type.block_size());
                            continue;
                        }

                        if !common.decrypt {
                            header.set_info(header_info.to_string());
                        }

                        let Some((key, iv)) =
                            log_error(Self::generate_key(kdf.clone(), &header, iv, cs, block_type))
                        else {
                            continue;
                        };

                        let Some(cipher) = log_error(Self::cs_cipher(block_type, cs, key, iv))
                        else {
                            continue;
                        };

                        let Some(data) = log_error(Self::run(cipher, &data, common.decrypt)) else {
                            continue;
                        };

                        log_error(common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}
