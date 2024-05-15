use crate::cmd::args::{Key, KeyArgs, Salt, SaltArgs};
use cipher::{kdf::Scrypt, KDF};
use clap::Args;

use super::KDFCommonArgs;

#[derive(Args, Clone)]
pub struct ScryptArgs {
    #[command(flatten)]
    pub key: KeyArgs,

    #[command(flatten)]
    salt: SaltArgs,

    #[command(flatten)]
    common: KDFCommonArgs,

    #[arg(short, long = "mem", default_value = "2097152")]
    #[arg(help = "cpu memory cost in bytes")]
    memory: usize,

    #[arg(short, long = "blk", default_value = "8")]
    #[arg(help = "block size in bytes")]
    block: usize,

    #[arg(short, long = "par", default_value = "1")]
    #[arg(help = "parallelation numbers")]
    parallel: usize,
}

impl ScryptArgs {
    pub fn scrypt(&self) -> anyhow::Result<Scrypt> {
        let (key, salt): (Key, Salt) = ((&self.key).try_into()?, (&self.salt).try_into()?);

        Ok(Scrypt::new(
            key.as_ref().to_vec(),
            salt.as_ref().to_vec(),
            self.memory,
            self.parallel,
            self.block,
        )?)
    }

    pub fn run(&self) -> anyhow::Result<Key> {
        let mut kdf = self.scrypt()?;
        let key = kdf.kdf(self.common.ksize)?;

        Ok(Key::new(key))
    }

    pub fn exe(self) {
        let key = self.run().unwrap();
        self.common.exe(&key);
    }

    pub(super) fn set_ksize(&mut self, ksize: usize) {
        self.common.set_ksize(ksize);
    }

    pub fn set_key(&mut self, key: Key) {
        self.key.set_key(key)
    }

    pub fn append_key(&mut self, key: Key) {
        self.key.append_key(key);
    }

    pub fn set_salt(&mut self, salt: Salt) {
        self.salt.set_salt(salt);
    }

    pub fn append_salt(&mut self, salt: Salt) {
        self.salt.append_salt(salt);
    }
}
