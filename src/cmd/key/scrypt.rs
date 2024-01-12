use crate::cmd::Cmd;
use anyhow::anyhow;
use cipher::{kdf::Scrypt, KDF};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::{fs::read, path::PathBuf};

use super::write_to_file_or_stdout;

#[derive(Clone)]
pub struct ScryptCmd;

impl Cmd for ScryptCmd {
    const NAME: &'static str = "scrypt";
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
            .arg(
                Arg::new("memory")
                    .short('m')
                    .long("memory")
                    .action(ArgAction::Set)
                    .required(false)
                    .default_value("2097152")
                    .value_parser(value_parser!(usize))
                    .help("memory size in bytes"),
            )
            .arg(
                Arg::new("block")
                    .short('b')
                    .long("block")
                    .action(ArgAction::Set)
                    .required(false)
                    .default_value("8")
                    .value_parser(value_parser!(usize))
                    .help("block size in bytes"),
            )
            .arg(
                Arg::new("paral")
                    .short('p')
                    .long("paral")
                    .action(ArgAction::Set)
                    .required(false)
                    .default_value("1")
                    .value_parser(value_parser!(usize))
                    .help("parallelization"),
            )
            .about("Scrypt")
    }

    fn run(&self, m: &ArgMatches) {
        let mut kdf = self.generate_kdf(m).unwrap();
        let size = m
            .get_one::<usize>("size")
            .copied()
            .expect("need to specified the key size");
        let key = kdf.kdf(size).unwrap();
        write_to_file_or_stdout(m, key.as_slice()).unwrap();
    }
}

impl ScryptCmd {
    pub fn generate_kdf(&self, m: &ArgMatches) -> anyhow::Result<Box<dyn KDF>> {
        let (k, s, m, b, p) = (
            m.get_one::<PathBuf>("key")
                .ok_or(anyhow!("not specified the key file"))?,
            m.get_one::<PathBuf>("salt"),
            m.get_one::<usize>("memory")
                .copied()
                .ok_or(anyhow!("not specified memory size"))? as usize,
            m.get_one::<usize>("block")
                .copied()
                .ok_or(anyhow!("not specified block size"))? as usize,
            m.get_one::<usize>("paral")
                .copied()
                .ok_or(anyhow!("not specified paral numbers"))? as usize,
        );

        let key = read(k).unwrap();
        let salt = match s {
            Some(f) => read(f)?,
            None => vec![],
        };

        Ok(Box::new(Scrypt::new(key, salt, m, p, b)?))
    }
}
