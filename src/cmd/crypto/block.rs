use cipher::{
    block_cipher::{AES128, AES192, AES256, SM4},
    BlockCipherX, Cipher, KDF,
};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::path::PathBuf;

use crate::cmd::{
    crypto::common_crypto,
    key::{Argon2Cmd, PBKDF1Cmd, PBKDF2Cmd, PlainCmd, ScryptCmd},
    Cmd,
};

pub fn common_subcommand(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("msg")
            .value_name("MESSAGE")
            .required(false)
            .action(ArgAction::Set)
            .value_parser(value_parser!(String))
            .help("to specified the message"),
    )
    .arg(
        Arg::new("output")
            .long("output")
            .short('o')
            .action(ArgAction::Append)
            .required(false)
            .value_parser(value_parser!(PathBuf))
            .help("to specify the output file path to save the key"),
    )
    .arg(
        Arg::new("file")
            .short('f')
            .long("file")
            .action(ArgAction::Append)
            .value_parser(value_parser!(PathBuf))
            .required(false)
            .help("to specified the file path"),
    )
    .arg(
        Arg::new("decrypt")
            .short('d')
            .long("is-decrypt")
            .action(ArgAction::SetTrue)
            .required(false)
            .help("the flag to decrypt all files or message"),
    )
    .subcommand(PlainCmd::cmd())
    .subcommand(PBKDF1Cmd::cmd())
    .subcommand(PBKDF2Cmd::cmd())
    .subcommand(ScryptCmd::cmd())
    .subcommand(Argon2Cmd::cmd())
}

pub fn common_run(m: &ArgMatches) -> anyhow::Result<Box<dyn KDF>> {
    let Some((name, sm)) = m.subcommand() else {
        anyhow::bail!("The block cipher need to specified KDF function to generate password")
    };

    let kdf = match name {
        PlainCmd::NAME => PlainCmd.generate_kdf(sm),
        PBKDF1Cmd::NAME => PBKDF1Cmd.generate_kdf(sm),
        PBKDF2Cmd::NAME => PBKDF2Cmd.generate_kdf(sm),
        ScryptCmd::NAME => ScryptCmd.generate_kdf(sm),
        Argon2Cmd::NAME => Argon2Cmd.generate_kdf(sm),
        _ => anyhow::bail!("not support the `{name}` kdf"),
    }?;

    Ok(kdf)
}

#[derive(Clone)]
pub struct SM4Cmd;

impl Cmd for SM4Cmd {
    const NAME: &'static str = "sm4";
    fn cmd() -> clap::Command {
        let c = Command::new(Self::NAME).subcommand_required(true);
        common_subcommand(c).about("SM4 block cipher")
    }

    fn run(&self, m: &clap::ArgMatches) {
        let c = self.generate_cipher(m).unwrap();
        common_crypto(c, m).unwrap();
    }
}

impl SM4Cmd {
    pub fn generate_block_cipher(
        &self,
        m: &ArgMatches,
    ) -> anyhow::Result<Vec<Box<dyn BlockCipherX + Sync + Send>>> {
        let mut kdf = common_run(m)?;
        let key = kdf.kdf(SM4::KEY_SIZE)?;

        let Ok(key) = key.try_into() else {
            anyhow::bail!(
                "cannot convert to sm4 key array with size {}",
                SM4::KEY_SIZE
            );
        };

        let sm4 = SM4::new(key);
        let nums = (m
            .get_many::<PathBuf>("file")
            .map(|x| x.count())
            .unwrap_or_default()
            + m.get_many::<PathBuf>("output")
                .map(|x| x.count())
                .unwrap_or_default()
            + m.get_one::<String>("msg").map(|_x| 1).unwrap_or_default())
        .max(1);
        let mut v: Vec<Box<dyn BlockCipherX + Sync + Send>> = Vec::with_capacity(nums);
        (0..(nums - 1)).for_each(|_| v.push(Box::new(sm4.clone())));
        v.push(Box::new(sm4));
        Ok(v)
    }

    pub fn generate_cipher(
        &self,
        m: &ArgMatches,
    ) -> anyhow::Result<Vec<Box<dyn Cipher + Send + Sync>>> {
        let b = self.generate_block_cipher(m)?;
        let mut c: Vec<Box<dyn Cipher + Send + Sync>> = Vec::with_capacity(b.len());
        for x in b {
            c.push(Box::new(x))
        }

        Ok(c)
    }
}

macro_rules! impl_block_cmd {
    ([$CMD1: ident, $NAME1: literal, $BC1: ty], $([$CMD2: ident, $NAME2: literal, $BC2: ty]),+) => {
        impl_block_cmd!([$CMD1, $NAME1, $BC1]);
        impl_block_cmd!($([$CMD2, $NAME2, $BC2]),+);
    };
    ([$CMD: ident, $NAME: literal, $BC: ty]) => {

        #[derive(Clone)]
        pub struct $CMD;

        impl Cmd for $CMD {
            const NAME: &'static str = $NAME;
            fn cmd() -> clap::Command {
                let c = Command::new(Self::NAME).subcommand_required(true);
                common_subcommand(c)
                .about(format!("{} block cipher", stringify!($BC)))
            }

            fn run(&self, m: &clap::ArgMatches) {
                let c = self.generate_cipher(m).unwrap();
                common_crypto(c, m).unwrap();
            }
        }

        impl $CMD {
            pub fn generate_block_cipher(
                &self,
                m: &ArgMatches,
            ) -> anyhow::Result<Vec<Box<dyn BlockCipherX + Sync + Send>>> {
                let mut kdf = common_run(m)?;
                let key = kdf.kdf(<$BC>::KEY_SIZE)?;

                let Ok(key) = key.try_into() else {
                    anyhow::bail!(
                        "cannot convert to aes key array with size {}",
                        SM4::KEY_SIZE
                    );
                };

                let block_cipher = <$BC>::new(key);
                let nums = (m
                    .get_many::<PathBuf>("file")
                    .map(|x| x.count())
                    .unwrap_or_default()
                    + m.get_many::<PathBuf>("output")
                        .map(|x| x.count())
                        .unwrap_or_default()
                    + m.get_one::<String>("msg").map(|_x| 1).unwrap_or_default())
                .max(1);
                let mut v: Vec<Box<dyn BlockCipherX + Sync + Send>> = Vec::with_capacity(nums);
                (0..(nums - 1)).for_each(|_| v.push(Box::new(block_cipher.clone())));
                v.push(Box::new(block_cipher));
                Ok(v)
            }

            pub fn generate_cipher(
                &self,
                m: &ArgMatches,
            ) -> anyhow::Result<Vec<Box<dyn Cipher + Send + Sync>>> {
                let b = self.generate_block_cipher(m)?;
                let mut c: Vec<Box<dyn Cipher + Send + Sync>> = Vec::with_capacity(b.len());
                for x in b {
                    c.push(Box::new(x))
                }

                Ok(c)
            }
        }
    };
}

impl_block_cmd!(
    [AES128Cmd, "aes128", AES128],
    [AES192Cmd, "aes192", AES192],
    [AES256Cmd, "aes256", AES256]
);
