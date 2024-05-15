use crate::cmd::args::{IVArgs, IVector, Key, Salt, SaltArgs};
use crate::cmd::config::MyConfig;
use crate::cmd::crypto::block::BlockCipherType;
use crate::cmd::crypto::header::Header;
use crate::cmd::crypto::CryptoCommonArgs;
use crate::cmd::info::Info;
use crate::cmd::kdf::KDFSubArgs;
use crate::log_error;
use cipher::ae::{AuthenticationCipherX, CCM, GCM};
use clap::{
    builder::{PossibleValuesParser, TypedValueParser},
    Args,
};
use std::thread;

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args))]
#[command(mut_group("salt", |g| g.id("nonce")))]
#[command(mut_arg("sfile", |a| a.long("nfile").value_name("NFILE").help("the nonce file path")))]
#[command(mut_arg("sstr", |a| a.long("nstr").value_name("NSTR").help("the nonce string")))]
#[command(mut_group("iv", |g| g.id("adata").required(false)))]
#[command(mut_arg("ivfile", |a| a.long("afile").value_name("AFILE").help("the associated data file path")))]
#[command(mut_arg("ivstr", |a| a.long("astr").value_name("ASTR").help("the associated data string")))]
#[command(
    about = "The Counter with Cipher Block Chaining-Message Authentication Code(NIST SP 800-38C)"
)]
pub struct CCMArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[arg(name = "type", short, long, default_value = "aes128")]
    pub r#type: BlockCipherType,

    #[arg(long="msize", value_parser = PossibleValuesParser::new(["4", "6", "8", "10", "12", "14", "16"]).map(|x| x.parse::<u8>().unwrap()))]
    #[arg(
        default_value = "16",
        value_name = "MAC-SIZE",
        help = "MAC size in byte"
    )]
    pub mac_size: u8,

    #[command(subcommand)]
    pub kdf: KDFSubArgs,

    #[command(flatten)]
    nonce: SaltArgs,

    #[command(flatten)]
    adata: IVArgs,
}

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args))]
#[command(mut_group("salt", |g| g.id("nonce")))]
#[command(mut_arg("sfile", |a| a.long("nfile").value_name("NFILE").help("the nonce file path")))]
#[command(mut_arg("sstr", |a| a.long("nstr").value_name("NSTR").help("the nonce string")))]
#[command(mut_group("iv", |g| g.id("adata").required(false)))]
#[command(mut_arg("ivfile", |a| a.long("afile").value_name("AFILE").help("the associated data file path")))]
#[command(mut_arg("ivstr", |a| a.long("astr").value_name("ASTR").help("the associated data string")))]
#[command(about = "The Galois/Counter Mode(GCM) and GMAC(NIST SP 800-38D)")]
pub struct GCMArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[arg(name = "type", short, long, default_value = "aes128")]
    pub r#type: BlockCipherType,

    #[arg(long="msize", value_parser = clap::value_parser!(u8).range(0..=16))]
    #[arg(
        default_value = "16",
        value_name = "MAC-SIZE",
        help = "MAC size in byte"
    )]
    pub mac_size: u8,

    #[command(subcommand)]
    pub kdf: KDFSubArgs,

    #[command(flatten)]
    nonce: SaltArgs,

    #[command(flatten)]
    adata: IVArgs,
}

impl CCMArgs {
    pub fn generate_key(&self, header: &Header) -> anyhow::Result<Key> {
        let mut kdf = self.kdf.clone();
        kdf.append_key(Key::from(header.digest()))?;
        kdf.append_key(Key::from(self.mac_size.to_be_bytes().to_vec()))?;
        if self.nonce.is_specified() {
            kdf.append_salt(Salt::try_from(&self.nonce)?)?;
        }

        if self.adata.is_specified() {
            kdf.append_salt(IVector::try_from(&self.adata)?)?
        }

        kdf.set_ksize(self.r#type.key_size());
        kdf.run()
    }

    pub fn ccm_cipher(
        &self,
        key: Key,
    ) -> anyhow::Result<Box<dyn AuthenticationCipherX + Send + Sync + 'static>> {
        let block_cipher = self.r#type.block_cipher(key)?;
        Ok(Box::new(CCM::new(block_cipher, self.mac_size as usize)?))
    }

    pub fn run(
        cipher: Box<dyn AuthenticationCipherX + Send + Sync + 'static>,
        data: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        let mut res = MyConfig::tmp_buf();
        if is_decrypt {
            cipher.auth_decrypt_x(nonce, associated_data, data, &mut res)?;
        } else {
            cipher.auth_encrypt_x(nonce, associated_data, data, &mut res)?;
        }

        Ok(res)
    }

    fn cipher_data(&self, data: &[u8], nonce: &[u8], associated_data: &[u8]) -> anyhow::Result<()> {
        let Some((data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let key = self.generate_key(&header)?;

        let cipher = self.ccm_cipher(key)?;
        let data = Self::run(cipher, data, nonce, associated_data, self.common.decrypt)?;

        if !self.common.decrypt {
            header.set_info(self.merge_name(&self.r#type.merge_name(&self.kdf)));
        }

        self.common.write_data(header, &data, &self.common.io)?;

        Ok(())
    }

    pub fn exe(mut self, pipe: Option<&[u8]>) {
        self.kdf.prompt_input_password().unwrap();
        self.common.assert_only_one_datasource(pipe).unwrap();

        let nonce = Salt::try_from(&self.nonce).unwrap().to_bytes();
        let adata = if self.adata.is_specified() {
            IVector::try_from(&self.adata).unwrap().to_bytes()
        } else {
            Vec::new()
        };
        let (nonce, adata) = (nonce.as_slice(), adata.as_slice());

        if let Some(pipe) = pipe {
            self.cipher_data(pipe, nonce, adata).unwrap();
            return;
        }

        if let Some(msg) = self.common.msg.as_deref() {
            self.cipher_data(msg.as_bytes(), nonce, adata).unwrap();
            return;
        }

        self.multiple_thread_to_run(nonce, adata);
    }

    fn multiple_thread_to_run(&self, nonce: &[u8], associated_data: &[u8]) {
        let (ios, cpus, header_info) = (
            self.common.io.clone().decompose().unwrap(),
            MyConfig::config().threads,
            self.merge_name(&self.r#type.merge_name(&self.kdf)),
        );

        if ios.is_empty() {
            return;
        }

        let header_info = header_info.as_str();

        thread::scope(|s| {
            for chunk in ios.chunks(ios.len().div_ceil(cpus)) {
                s.spawn(move || {
                    for io_arg in chunk {
                        let Some((data, mut header)) =
                            log_error(self.common.read_from_ioargs(io_arg)).flatten()
                        else {
                            continue;
                        };

                        if !self.common.decrypt {
                            header.set_info(header_info.to_string());
                        }

                        let Some(key) = log_error(self.generate_key(&header)) else {
                            continue;
                        };

                        let Some(cipher) = log_error(self.ccm_cipher(key)) else {
                            continue;
                        };

                        let Some(data) = log_error(Self::run(
                            cipher,
                            &data,
                            nonce,
                            associated_data,
                            self.common.decrypt,
                        )) else {
                            continue;
                        };

                        log_error(self.common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}

impl GCMArgs {
    pub fn generate_key(&self, header: &Header) -> anyhow::Result<Key> {
        let mut kdf = self.kdf.clone();
        kdf.append_key(Key::from(
            (self.mac_size as u32)
                .rotate_right(header.digest()[0] as u32)
                .to_be_bytes()
                .to_vec(),
        ))?;
        kdf.append_key(Key::from(header.digest()))?;
        if self.nonce.is_specified() {
            kdf.append_salt(Salt::try_from(&self.nonce)?)?;
        }

        if self.adata.is_specified() {
            kdf.append_salt(IVector::try_from(&self.adata)?)?
        }

        kdf.set_ksize(self.r#type.key_size());
        kdf.run()
    }

    pub fn gcm_cipher(
        &self,
        key: Key,
    ) -> anyhow::Result<Box<dyn AuthenticationCipherX + Send + Sync + 'static>> {
        let block_cipher = self.r#type.block_cipher(key)?;
        Ok(Box::new(GCM::new(block_cipher, self.mac_size as usize)?))
    }

    pub fn run(
        cipher: Box<dyn AuthenticationCipherX + Send + Sync + 'static>,
        data: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        CCMArgs::run(cipher, data, nonce, associated_data, is_decrypt)
    }

    fn cipher_data(&self, data: &[u8], nonce: &[u8], associated_data: &[u8]) -> anyhow::Result<()> {
        let Some((data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let key = self.generate_key(&header)?;

        let cipher = self.gcm_cipher(key)?;
        let data = Self::run(cipher, data, nonce, associated_data, self.common.decrypt)?;

        if !self.common.decrypt {
            header.set_info(self.merge_name(&self.r#type.merge_name(&self.kdf)));
        }

        self.common.write_data(header, &data, &self.common.io)?;

        Ok(())
    }

    pub fn exe(mut self, pipe: Option<&[u8]>) {
        self.kdf.prompt_input_password().unwrap();
        self.common.assert_only_one_datasource(pipe).unwrap();

        let nonce = Salt::try_from(&self.nonce).unwrap().to_bytes();
        let adata = if self.adata.is_specified() {
            IVector::try_from(&self.adata).unwrap().to_bytes()
        } else {
            Vec::new()
        };
        let (nonce, adata) = (nonce.as_slice(), adata.as_slice());

        if let Some(pipe) = pipe {
            self.cipher_data(pipe, nonce, adata).unwrap();
            return;
        }

        if let Some(msg) = self.common.msg.as_deref() {
            self.cipher_data(msg.as_bytes(), nonce, adata).unwrap();
            return;
        }

        self.multiple_thread_to_run(nonce, adata);
    }

    fn multiple_thread_to_run(&self, nonce: &[u8], associated_data: &[u8]) {
        let (ios, cpus, header_info) = (
            self.common.io.clone().decompose().unwrap(),
            MyConfig::config().threads,
            self.merge_name(&self.r#type.merge_name(&self.kdf)),
        );

        if ios.is_empty() {
            return;
        }

        let header_info = header_info.as_str();

        thread::scope(|s| {
            for chunk in ios.chunks(ios.len().div_ceil(cpus)) {
                s.spawn(move || {
                    for io_arg in chunk {
                        let Some((data, mut header)) =
                            log_error(self.common.read_from_ioargs(io_arg)).flatten()
                        else {
                            continue;
                        };

                        if !self.common.decrypt {
                            header.set_info(header_info.to_string());
                        }

                        let Some(key) = log_error(self.generate_key(&header)) else {
                            continue;
                        };

                        let Some(cipher) = log_error(self.gcm_cipher(key)) else {
                            continue;
                        };

                        let Some(data) = log_error(Self::run(
                            cipher,
                            &data,
                            nonce,
                            associated_data,
                            self.common.decrypt,
                        )) else {
                            continue;
                        };

                        log_error(self.common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}
