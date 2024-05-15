use crate::cmd::args::Key;
use crate::cmd::crypto::block::BlockCipherType;
use crate::cmd::kdf::KDFSubArgs;
use cipher::mac::CMAC;
use cipher::MAC;
use clap::Args;
use std::io::Write;
use std::path::PathBuf;

#[derive(Args)]
#[command(defer(KDFSubArgs::for_crypto_args))]
#[command(about = "CMAC(NIST SP 800-38B)")]
pub struct CMACArgs {
    #[arg(value_name = "STRING", allow_hyphen_values = true)]
    #[arg(help = "hash string")]
    str: Option<String>,

    #[arg(short = 'f', long = "file")]
    #[arg(help = "the file path")]
    file: Option<PathBuf>,

    #[arg(short = 't', long = "type", default_value = "aes128")]
    block_type: BlockCipherType,

    #[command(subcommand)]
    kdf: KDFSubArgs,
}

impl CMACArgs {
    pub fn cmac(&self, key: Key) -> anyhow::Result<Box<dyn MAC + Send + Sync + 'static>> {
        let block_cipher = self.block_type.block_cipher(key)?;
        Ok(Box::new(CMAC::new(block_cipher)?))
    }

    pub fn run(&self, pipe: Option<&[u8]>) -> anyhow::Result<Vec<u8>> {
        let mut kdf = self.kdf.clone();
        kdf.set_ksize(self.block_type.key_size());
        let key = kdf.run()?;
        let mut mac = self.cmac(key)?;

        if let Some(pipe) = pipe {
            mac.write_all(pipe)?;
        }

        if let Some(s) = self.str.as_deref() {
            mac.write_all(s.as_bytes())?;
        }

        if let Some(f) = self.file.as_deref() {
            let s = std::fs::read(f)?;
            mac.write_all(&s)?;
        }

        Ok(mac.mac())
    }
}
