use clap::Args;

use crate::cmd::{
    args::{Key, KeyArgs, Salt, SaltArgs},
    hash::HashSubCmd,
};

use super::KDFCommonArgs;

#[derive(Args, Clone)]
#[command(about = "input content as key, adapt(hash(key | salt))")]
#[command(defer(HashSubCmd::hide_std_args), mut_group("salt", |g| g.required(false)))]
pub struct PlainArgs {
    #[command(flatten)]
    pub key: KeyArgs,

    #[command(flatten)]
    salt: SaltArgs,

    #[command(flatten)]
    common: KDFCommonArgs,

    #[arg(long)]
    #[arg(
        help = r#"if the input the length less than `ksize`, append 0x00 to output
otherwise truncate to `ksize`
"#
    )]
    adapt: bool,

    #[command(subcommand)]
    pub h: Option<HashSubCmd>,
}

impl PlainArgs {
    pub fn run(self) -> anyhow::Result<Key> {
        let mut key: Key = (&self.key).try_into()?;

        if let Some(h) = self.h {
            let data = if self.salt.is_specified() {
                let salt = Salt::try_from(&self.salt)?;
                h.run(Some([key.as_ref(), salt.as_ref()].iter()))
            } else {
                h.run(Some([key.as_ref()].iter()))
            };
            key = Key::new(data);
        }

        if self.adapt {
            if key.len() < self.common.ksize {
                key.extend(vec![0; self.common.ksize - key.len()]);
            } else {
                key.truncate(self.common.ksize);
            }
        } else {
            anyhow::ensure!(
                key.len() == self.common.ksize,
                "key byte length not equal to {}",
                self.common.ksize
            );
        }

        Ok(key)
    }

    pub fn exe(self) {
        let (common, key) = (self.common.clone(), self.run().unwrap());
        common.exe(&key);
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
