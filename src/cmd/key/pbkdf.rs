use std::{fs::read, path::PathBuf};

use anyhow::anyhow;
use cipher::{kdf::PBKDF1, kdf::PBKDF2, KDF};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

use crate::cmd::{key::write_to_file_or_stdout, mac::HMACCmd, Cmd, HashCmd};

#[derive(Clone)]
pub struct PBKDF1Cmd;

#[derive(Clone)]
pub struct PBKDF2Cmd;

impl Cmd for PBKDF1Cmd {
    const NAME: &'static str = "pbkdf1";
    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .arg(
                Arg::new("key")
                    .short('k')
                    .long("key")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true)
                    .help("password file"),
            )
            .arg(
                Arg::new("salt")
                    .short('x')
                    .long("salt")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("salt file"),
            )
            .arg(
                Arg::new("rounds")
                    .short('r')
                    .long("rounds")
                    .action(ArgAction::Set)
                    .required(true)
                    .value_parser(value_parser!(u64).range(1..=u64::MAX))
                    .help("iteration rounds"),
            )
            .arg(
                Arg::new("output")
                    .long("output")
                    .short('o')
                    .action(ArgAction::Set)
                    .required(false)
                    .value_parser(value_parser!(PathBuf))
                    .help("to specify the output file path to save the key"),
            )
            .arg(
                Arg::new("size")
                    .short('s')
                    .long("size")
                    .action(ArgAction::Set)
                    .required(false)
                    .value_parser(value_parser!(usize))
                    .help("key byte size, it will be the KDF max key size if not specified"),
            )
            .subcommand(HashCmd::cmd())
            .subcommand_required(true)
            .about("PBKDF1")
    }

    fn run(&self, m: &clap::ArgMatches) {
        let mut kdf = self.generate_kdf(m).unwrap();
        let size = m
            .get_one::<usize>("size")
            .copied()
            .unwrap_or_else(|| kdf.max_key_size());
        let key = kdf.kdf(size).unwrap();
        write_to_file_or_stdout(m, key.as_slice()).unwrap();
    }
}

impl Cmd for PBKDF2Cmd {
    const NAME: &'static str = "pbkdf2";
    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .arg(
                Arg::new("key")
                    .short('k')
                    .long("key")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true)
                    .help("password file"),
            )
            .arg(
                Arg::new("salt")
                    .short('x')
                    .long("salt")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("salt file"),
            )
            .arg(
                Arg::new("rounds")
                    .short('r')
                    .long("rounds")
                    .action(ArgAction::Set)
                    .required(true)
                    .value_parser(value_parser!(u64).range(1..=u64::MAX))
                    .help("iteration rounds"),
            )
            .arg(
                Arg::new("output")
                    .long("output")
                    .short('o')
                    .action(ArgAction::Set)
                    .required(false)
                    .value_parser(value_parser!(PathBuf))
                    .help("to specify the output file path to save the key"),
            )
            .arg(
                Arg::new("size")
                    .short('s')
                    .long("size")
                    .action(ArgAction::Set)
                    .required(false)
                    .default_value("32")
                    .value_parser(value_parser!(usize))
                    .help("key byte size"),
            )
            .subcommand(HMACCmd::cmd())
            .subcommand_required(true)
            .about("PBKDF2")
    }

    fn run(&self, m: &clap::ArgMatches) {
        let mut kdf = self.generate_kdf(m).unwrap();
        let size = m
            .get_one::<usize>("size")
            .copied()
            .expect("need to specified the key size");
        let key = kdf.kdf(size).unwrap();
        write_to_file_or_stdout(m, key.as_slice()).unwrap();
    }
}

impl PBKDF1Cmd {
    pub fn generate_kdf(&self, m: &ArgMatches) -> anyhow::Result<Box<dyn KDF>> {
        let (k, s, r) = (
            m.get_one::<PathBuf>("key")
                .ok_or(anyhow!("not specified the key file"))?,
            m.get_one::<PathBuf>("salt"),
            m.get_one::<u64>("rounds")
                .copied()
                .ok_or(anyhow!("not specified the iteration rounds"))? as usize,
        );

        let Some((HashCmd::NAME, hm)) = m.subcommand() else {
            anyhow::bail!("pbkdf1 need to specified the hash function",);
        };

        let hasher = HashCmd::new(&[]).hasher_cmd(hm).generate_hasher()?;

        let key = read(k).unwrap();
        let salt = match s {
            Some(f) => read(f)?,
            None => vec![],
        };

        Ok(Box::new(PBKDF1::new(hasher, key, salt, r)?))
    }
}

impl PBKDF2Cmd {
    pub fn generate_kdf(&self, m: &ArgMatches) -> anyhow::Result<Box<dyn KDF>> {
        let (k, s, r) = (
            m.get_one::<PathBuf>("key")
                .ok_or(anyhow!("not specified the key file"))?,
            m.get_one::<PathBuf>("salt"),
            m.get_one::<u64>("rounds")
                .copied()
                .ok_or(anyhow!("not specified the iteration rounds"))? as usize,
        );

        let Some((HMACCmd::NAME, hm)) = m.subcommand() else {
            anyhow::bail!("pbkdf1 need to specified the hash function",);
        };

        let hmac = HMACCmd.generate_hmac(hm)?;

        let key = read(k).unwrap();
        let salt = match s {
            Some(f) => read(f)?,
            None => vec![],
        };

        Ok(Box::new(PBKDF2::new(hmac, key, salt, r)?))
    }
}
