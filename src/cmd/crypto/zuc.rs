use crate::cmd::args::{Key, Salt};
use crate::cmd::config::MyConfig;
use crate::cmd::crypto::header::Header;
use crate::cmd::crypto::mode::ECBArgs;
use crate::cmd::crypto::CryptoCommonArgs;
use crate::cmd::info::Info;
use crate::cmd::kdf::KDFSubArgs;
use crate::log_error;
use cipher::stream_cipher::zuc::{ZUCKey, ZUC};
use cipher::stream_cipher::StreamCipherX;
use clap::Args;
use std::thread;

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args))]
#[command(about = "ZUC stream cipher")]
pub struct ZUCArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,
    #[arg(long)]
    count: u32,
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..32))]
    bearer: u8,
    #[arg(long)]
    direction: bool,

    #[command(subcommand)]
    kdf: KDFSubArgs,
}

impl ZUCArgs {
    fn generate_key(&self, header: &Header) -> anyhow::Result<Key> {
        let mut kdf = self.kdf.clone();
        kdf.append_salt(Salt::from(header.file_name()))?;
        kdf.append_salt(Salt::from(Vec::from(self.count.to_be_bytes())))?;
        kdf.append_salt(Salt::from(header.digest()))?;
        kdf.append_salt(Salt::from(vec![self.bearer, self.direction as u8]))?;

        kdf.set_ksize(ZUCKey::KEY_SIZE);
        kdf.run()
    }

    pub fn zuc_cipher(
        &self,
        key: Key,
    ) -> anyhow::Result<Box<dyn StreamCipherX + Send + Sync + 'static>> {
        Ok(Box::new(ZUC::new(
            self.count,
            self.bearer,
            self.direction,
            key.try_into()?,
        )))
    }

    pub fn run(
        cipher: Box<dyn StreamCipherX + Send + Sync + 'static>,
        data: &[u8],
        is_decrypt: bool,
    ) -> anyhow::Result<Vec<u8>> {
        ECBArgs::run(cipher, data, is_decrypt)
    }
    fn cipher_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let Some((data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let key = self.generate_key(&header)?;

        let cipher = self.zuc_cipher(key)?;
        let data = Self::run(cipher, data, self.common.decrypt)?;

        if !self.common.decrypt {
            header.set_info(self.merge_name(&self.kdf));
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
            self.merge_name(&self.kdf),
        );

        if ios.is_empty() {
            return;
        }

        let (zuc, header_info) = (&self, header_info.as_str());

        thread::scope(|s| {
            for chunk in ios.chunks(ios.len().div_ceil(cpus)) {
                s.spawn(move || {
                    for io_arg in chunk {
                        let Some((data, mut header)) =
                            log_error(zuc.common.read_from_ioargs(io_arg)).flatten()
                        else {
                            continue;
                        };

                        if !zuc.common.decrypt {
                            header.set_info(header_info.to_string());
                        }

                        let Some(key) = log_error(zuc.generate_key(&header)) else {
                            continue;
                        };

                        let Some(cipher) = log_error(zuc.zuc_cipher(key)) else {
                            continue;
                        };

                        let Some(data) = log_error(Self::run(cipher, &data, zuc.common.decrypt))
                        else {
                            continue;
                        };

                        log_error(zuc.common.write_data(header, &data, io_arg));
                    }
                });
            }
        });
    }
}
