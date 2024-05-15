use cipher::{
    kdf::{PBKDF1, PBKDF2},
    prf::HMAC,
    KDF,
};
use clap::{value_parser, Args};
use crypto_hash::DigestX;

use crate::cmd::{
    args::{Key, KeyArgs, Salt, SaltArgs},
    hash::HashSubCmd,
    mac::hmac::HMACArgs,
};

use super::KDFCommonArgs;

#[derive(Args, Clone)]
#[command(defer(HashSubCmd::hide_std_args))]
#[command(mut_group("salt", |g| g.required(false)))]
pub struct PBKDFArgs {
    #[command(subcommand)]
    pub h: HashSubCmd,

    #[command(flatten)]
    pub key: KeyArgs,

    #[command(flatten)]
    salt: SaltArgs,

    #[command(flatten)]
    common: KDFCommonArgs,

    #[arg(long, value_parser = value_parser!(u64).range(1..))]
    #[arg(default_value = "10000", help = "iteration rounds")]
    round: u64,
}

impl PBKDFArgs {
    pub fn pbkdf1(&self) -> anyhow::Result<PBKDF1<Box<dyn DigestX>>> {
        anyhow::ensure!(
            self.common.ksize <= self.h.digest_size(),
            "key size `{}` cannot great than the digest size `{}`",
            self.common.ksize,
            self.h.digest_size()
        );

        let key = Key::try_from(&self.key)?.to_bytes();
        let salt = if self.salt.is_specified() {
            Salt::try_from(&self.salt)?.to_bytes()
        } else {
            vec![]
        };

        let kdf = PBKDF1::new(self.h.hasher()?, key, salt, usize::try_from(self.round)?)?;

        Ok(kdf)
    }

    pub fn pbkdf1_run(&self) -> anyhow::Result<Key> {
        let mut kdf = self.pbkdf1()?;
        let key = kdf.kdf(self.common.ksize)?;

        Ok(Key::new(key))
    }

    pub fn pbkdf1_exe(self) {
        let key = self.pbkdf1_run().unwrap();
        self.common.exe(&key);
    }

    pub fn pbkdf2(&self) -> anyhow::Result<PBKDF2<HMAC<Box<dyn DigestX>>>> {
        anyhow::ensure!(
            self.common.ksize <= self.h.digest_size(),
            "key size `{}` cannot great than the digest size `{}`",
            self.common.ksize,
            self.h.digest_size()
        );

        let key = Key::try_from(&self.key)?.to_bytes();
        let salt = if self.salt.is_specified() {
            Salt::try_from(&self.salt)?.to_bytes()
        } else {
            vec![]
        };
        let hmac = HMACArgs::from_hash_and_key(self.h.clone(), self.key.clone()).prf()?;

        let kdf = PBKDF2::new(hmac, key, salt, usize::try_from(self.round)?)?;

        Ok(kdf)
    }

    pub fn pbkdf2_run(&self) -> anyhow::Result<Key> {
        let mut kdf = self.pbkdf2()?;
        let key = kdf.kdf(self.common.ksize)?;

        Ok(Key::new(key))
    }

    pub fn pbkdf2_exe(self) {
        let key = self.pbkdf2_run().unwrap();
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
