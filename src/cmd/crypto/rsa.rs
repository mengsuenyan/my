use crate::cmd::args::{IVArgs, IVector, KeyArgs};
use crate::cmd::config::MyConfig;
use crate::cmd::crypto::CryptoCommonArgs;
use crate::cmd::hash::HashSubCmd;
use crate::cmd::info::Info;
use crate::cmd::sign::RsaArgs as ParseKey;
use crate::log_error;
use anyhow::Error;
use cipher::rsa::{
    OAEPDecrypt, OAEPDecryptStream, OAEPEncrypt, OAEPEncryptStream, PKCS1Decrypt,
    PKCS1DecryptStream, PKCS1Encrypt, PKCS1EncryptStream,
};
use cipher::{DefaultRand, StreamDecrypt, StreamEncrypt};
use clap::{Args, Subcommand};
use crypto_hash::DigestX;
use std::thread;

#[derive(Args)]
#[command(about = "asymmetric encrypt/decrypt by the RSA")]
pub struct RSAArgs {
    #[command(subcommand)]
    sub_cmd: RSASubArgs,
}

#[derive(Subcommand)]
pub enum RSASubArgs {
    PKCS1(Box<PKCS1Args>),
    OAEP(Box<OAEPArgs>),
}

#[derive(Args)]
#[command(mut_group("key", |g| g.required(true)))]
#[command(mut_arg("kfile", |a| a.help("the key file that generated by the `my key rsa` with no `--0x` parameter")))]
#[command(mut_arg("kstr", |a| a.help("the hex public key string generated by the `my key rsa --0x`")))]
#[command(defer(HashSubCmd::hide_std_args))]
#[command(about = r#"Public Key Cryptography Standards v1.5(PKCS1)
RFC 8017
PKCS #1: RSA Cryptography Specification Version 2.2
"#)]
pub struct PKCS1Args {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[command(flatten)]
    key: KeyArgs,
}

#[derive(Args)]
#[command(mut_group("key", |g| g.required(true)))]
#[command(mut_group("iv", |g| g.id("label").required(false)))]
#[command(mut_arg("kfile", |a| a.help("the key file that generated by the `my key rsa` with no `--0x` parameter")))]
#[command(mut_arg("kstr", |a| a.help("the hex public key string generated by the `my key rsa --0x`")))]
#[command(mut_arg("ivfile", |a| a.long("lfile").help("The OAEP label file path")))]
#[command(mut_arg("ivstr", |a| a.long("lstr").help("The OAEP label string")))]
#[command(defer(HashSubCmd::hide_std_args))]
#[command(about = r#"Optimal Asymmetric Encryption Padding(OAEP)
RFC 8017
PKCS #1: RSA Cryptography Specification Version 2.2
"#)]
pub struct OAEPArgs {
    #[command(flatten)]
    common: CryptoCommonArgs,

    #[command(flatten)]
    key: KeyArgs,

    #[command(flatten)]
    label: IVArgs,

    #[command(subcommand)]
    h: HashSubCmd,
}

impl RSAArgs {
    pub fn exe(self, pipe: Option<&[u8]>) {
        match self.sub_cmd {
            RSASubArgs::PKCS1(a) => a.exe(pipe),
            RSASubArgs::OAEP(a) => a.exe(pipe),
        }
    }
}

impl PKCS1Args {
    pub fn pkcs1_decrypt(&self) -> anyhow::Result<PKCS1DecryptStream<DefaultRand>> {
        let key = ParseKey::private_key(&self.key)?;
        let rng = DefaultRand::default();
        Ok(PKCS1DecryptStream::from(PKCS1Decrypt::new(key, rng)?))
    }

    pub fn pkcs1_encrypt(&self) -> anyhow::Result<PKCS1EncryptStream<DefaultRand>> {
        let key = ParseKey::public_key(&self.key)?;
        let rng = DefaultRand::default();
        Ok(PKCS1EncryptStream::from(PKCS1Encrypt::new(key, rng)?))
    }

    fn cipher_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let Some((mut data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let mut res = MyConfig::tmp_buf();

        if self.common.decrypt {
            let mut cipher = self.pkcs1_decrypt()?;
            let finish = cipher.stream_decrypt(&mut data, &mut res)?;
            let _ = finish.finish(&mut res)?;
        } else {
            header.set_info(self.name());

            let mut cipher = self.pkcs1_encrypt()?;
            let finish = cipher.stream_encrypt(&mut data, &mut res)?;
            let _ = finish.finish(&mut res)?;
        }

        self.common.write_data(header, &res, &self.common.io)?;

        Ok(())
    }

    pub fn exe(self, pipe: Option<&[u8]>) {
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
            self.name(),
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

                        let (mut res, mut data) = (MyConfig::tmp_buf(), data.as_slice());
                        if self.common.decrypt {
                            let Some(mut cipher) = log_error(self.pkcs1_decrypt()) else {
                                continue;
                            };

                            let Some(finish) = log_error(
                                cipher
                                    .stream_decrypt(&mut data, &mut res)
                                    .map_err(Error::from),
                            ) else {
                                continue;
                            };
                            let Some(_) = log_error(finish.finish(&mut res).map_err(Error::from))
                            else {
                                continue;
                            };
                        } else {
                            header.set_info(header_info.to_string());
                            let Some(mut cipher) = log_error(self.pkcs1_encrypt()) else {
                                continue;
                            };

                            let Some(finish) = log_error(
                                cipher
                                    .stream_encrypt(&mut data, &mut res)
                                    .map_err(Error::from),
                            ) else {
                                continue;
                            };
                            let Some(_) = log_error(finish.finish(&mut res).map_err(Error::from))
                            else {
                                continue;
                            };
                        }

                        log_error(self.common.write_data(header, &res, io_arg));
                    }
                });
            }
        });
    }
}

impl OAEPArgs {
    pub fn oaep_decrypt(&self) -> anyhow::Result<OAEPDecryptStream<Box<dyn DigestX>, DefaultRand>> {
        let key = ParseKey::private_key(&self.key)?;
        let hasher = self.h.hasher()?;
        let rng = DefaultRand::default();
        let label = if self.label.is_specified() {
            IVector::try_from(&self.label)?.to_bytes()
        } else {
            vec![]
        };

        Ok(OAEPDecryptStream::from(OAEPDecrypt::new(
            key,
            hasher,
            rng,
            label.as_slice(),
        )?))
    }

    pub fn oaep_encrypt(&self) -> anyhow::Result<OAEPEncryptStream<Box<dyn DigestX>, DefaultRand>> {
        let key = ParseKey::public_key(&self.key)?;
        let rng = DefaultRand::default();
        let label = if self.label.is_specified() {
            IVector::try_from(&self.label)?.to_bytes()
        } else {
            vec![]
        };

        let hasher = self.h.hasher()?;
        Ok(OAEPEncryptStream::from(OAEPEncrypt::new(
            key,
            hasher,
            rng,
            label.as_slice(),
        )?))
    }

    fn cipher_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let Some((mut data, mut header)) = self.common.read_data(data, &self.common.io)? else {
            return Ok(());
        };

        let mut res = MyConfig::tmp_buf();

        if self.common.decrypt {
            let mut cipher = self.oaep_decrypt()?;
            let finish = cipher.stream_decrypt(&mut data, &mut res)?;
            let _ = finish.finish(&mut res)?;
        } else {
            header.set_info(self.merge_name(&self.h));

            let mut cipher = self.oaep_encrypt()?;
            let finish = cipher.stream_encrypt(&mut data, &mut res)?;
            let _ = finish.finish(&mut res)?;
        }

        self.common.write_data(header, &res, &self.common.io)?;

        Ok(())
    }

    pub fn exe(self, pipe: Option<&[u8]>) {
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
            self.merge_name(&self.h),
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

                        let (mut res, mut data) = (MyConfig::tmp_buf(), data.as_slice());
                        if self.common.decrypt {
                            let Some(mut cipher) = log_error(self.oaep_decrypt()) else {
                                continue;
                            };

                            let Some(finish) = log_error(
                                cipher
                                    .stream_decrypt(&mut data, &mut res)
                                    .map_err(Error::from),
                            ) else {
                                continue;
                            };
                            let Some(_) = log_error(finish.finish(&mut res).map_err(Error::from))
                            else {
                                continue;
                            };
                        } else {
                            header.set_info(header_info.to_string());
                            let Some(mut cipher) = log_error(self.oaep_encrypt()) else {
                                continue;
                            };

                            let Some(finish) = log_error(
                                cipher
                                    .stream_encrypt(&mut data, &mut res)
                                    .map_err(Error::from),
                            ) else {
                                continue;
                            };
                            let Some(_) = log_error(finish.finish(&mut res).map_err(Error::from))
                            else {
                                continue;
                            };
                        }

                        log_error(self.common.write_data(header, &res, io_arg));
                    }
                });
            }
        });
    }
}
