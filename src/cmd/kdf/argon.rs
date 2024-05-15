use std::path::PathBuf;

use cipher::{
    kdf::{Argon2, ArgonParamsBuilder},
    KDF,
};
use clap::{builder::EnumValueParser, Args, ValueEnum};

use crate::cmd::args::{Key, KeyArgs, Salt, SaltArgs};

use super::KDFCommonArgs;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Argon2Type {
    #[value(name = "argon2d")]
    Argon2d,
    #[value(name = "argon2i")]
    Argon2i,
    #[value(name = "argon2id")]
    Argon2id,
}

#[derive(Args, Clone)]
pub struct Argon2Args {
    #[command(flatten)]
    pub key: KeyArgs,

    #[command(flatten)]
    salt: SaltArgs,

    #[command(flatten)]
    common: KDFCommonArgs,

    #[arg(long = "mem", default_value = "2097152")]
    #[arg(help = "memory size in kiobytes")]
    mem: u32,

    #[arg(long, default_value = "1")]
    #[arg(help = "iteration times")]
    round: u32,

    #[arg(long = "par", default_value = "4")]
    #[arg(help = "parallelation numbers")]
    parallel: u32,

    #[arg(long = "type", default_value = "argon2id", value_parser = EnumValueParser::<Argon2Type>::new())]
    r#type: Argon2Type,

    #[arg(long)]
    #[arg(help = "optional secret file path")]
    secret: Option<PathBuf>,

    #[arg(long)]
    #[arg(help = "optional associate data file path")]
    associate: Option<PathBuf>,
}

impl Argon2Args {
    pub fn argon2(&self) -> anyhow::Result<Argon2> {
        let argon2 = match self.r#type {
            Argon2Type::Argon2d => ArgonParamsBuilder::argon2d(),
            Argon2Type::Argon2i => ArgonParamsBuilder::argon2i(),
            Argon2Type::Argon2id => ArgonParamsBuilder::argon2id(),
        };

        let secret = if let Some(secret) = self.secret.as_deref() {
            std::fs::read(secret)?
        } else {
            vec![]
        };

        let ass = if let Some(ass) = self.associate.as_deref() {
            std::fs::read(ass)?
        } else {
            vec![]
        };

        let (key, salt): (Key, Salt) = ((&self.key).try_into()?, (&self.salt).try_into()?);

        Ok(argon2
            .degree_of_parallelism(self.parallel)
            .tag_len(u32::try_from(self.common.ksize)?)
            .mem_size(self.mem)
            .number_of_passes(self.round)
            .build_with_secret_associated(secret, ass)?
            .argon2(key.as_ref().to_vec(), salt.as_ref().to_vec())?)
    }

    pub fn run(&self) -> anyhow::Result<Key> {
        let mut argon2 = self.argon2()?;
        Ok(Key::new(argon2.kdf(self.common.ksize)?))
    }

    pub fn exe(self) {
        let v = self.run().unwrap();
        self.common.exe(&v);
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
