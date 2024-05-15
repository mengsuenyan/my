use std::{io::Write, path::PathBuf};

use cipher::{prf::HMAC, MAC};
use clap::Args;
use crypto_hash::DigestX;

use crate::cmd::{
    args::{Key, KeyArgs},
    hash::HashSubCmd,
};

#[derive(Args)]
#[command(defer(HashSubCmd::hide_std_args))]
pub struct HMACArgs {
    #[arg(value_name = "STRING", allow_hyphen_values = true)]
    #[arg(help = "hash string")]
    str: Option<String>,

    #[arg(short = 'f', long = "file")]
    #[arg(help = "the file path")]
    file: Option<PathBuf>,

    #[command(flatten)]
    key: KeyArgs,

    #[command(subcommand)]
    h: HashSubCmd,
}

impl HMACArgs {
    pub fn from_hash_and_key(h: HashSubCmd, key: KeyArgs) -> Self {
        Self {
            str: None,
            file: None,
            key,
            h,
        }
    }

    pub fn prf(&self) -> anyhow::Result<HMAC<Box<dyn DigestX>>> {
        let hasher = self.h.hasher()?;
        let key: Key = (&self.key).try_into()?;
        let mac = HMAC::new(hasher, key.as_ref().to_vec())?;
        Ok(mac)
    }

    pub fn run(&self, pipe: Option<&[u8]>) -> anyhow::Result<Vec<u8>> {
        let mut mac = self.prf()?;

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
