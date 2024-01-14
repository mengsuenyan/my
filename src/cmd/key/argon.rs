use crate::cmd::Cmd;
use anyhow::anyhow;
use cipher::{kdf::ArgonParamsBuilder, KDF};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::{fs::read, path::PathBuf};

use super::write_to_file_or_stdout;

#[derive(Clone)]
pub struct Argon2Cmd;

impl Cmd for Argon2Cmd {
    const NAME: &'static str = "argon2";
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
                    .value_parser(value_parser!(u32))
                    .help("key byte size"),
            )
            .arg(
                Arg::new("memory")
                    .short('m')
                    .long("memory")
                    .action(ArgAction::Set)
                    .required(false)
                    .default_value("2097152")
                    .value_parser(value_parser!(u32))
                    .help("memory size in kiobytes"),
            )
            .arg(
                Arg::new("times")
                    .short('t')
                    .long("times")
                    .action(ArgAction::Set)
                    .required(false)
                    .default_value("1")
                    .value_parser(value_parser!(u32))
                    .help("iteration times"),
            )
            .arg(
                Arg::new("paral")
                    .short('p')
                    .long("paral")
                    .action(ArgAction::Set)
                    .required(false)
                    .default_value("4")
                    .value_parser(value_parser!(u32))
                    .help("parallelization"),
            )
            .arg(
                Arg::new("type")
                    .long("type")
                    .action(ArgAction::Set)
                    .required(false)
                    .default_value("argon2id")
                    .value_parser(["argon2d", "argon2i", "argon2id"])
                    .help("argon2 type"),
            )
            .arg(
                Arg::new("secret")
                    .long("secret")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("secret file"),
            )
            .arg(
                Arg::new("associate")
                    .long("associate")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("associate data file"),
            )
            .about("Argon2")
    }

    fn run(&self, m: &ArgMatches) {
        let mut kdf = self.generate_kdf(m).unwrap();
        let l = kdf.max_key_size();
        let key = kdf.kdf(l).unwrap();
        write_to_file_or_stdout(m, key.as_slice()).unwrap();
    }
}

impl Argon2Cmd {
    pub fn generate_kdf(&self, m: &ArgMatches) -> anyhow::Result<Box<dyn KDF>> {
        let (k, s, p, tag, mem, times, secret, associate) = (
            m.get_one::<PathBuf>("key")
                .ok_or(anyhow!("not specified the key file"))?,
            m.get_one::<PathBuf>("salt"),
            m.get_one::<u32>("paral")
                .copied()
                .ok_or(anyhow!("not specified paral numbers"))?,
            m.get_one::<u32>("size")
                .copied()
                .ok_or(anyhow!("not specified key size"))?,
            m.get_one::<u32>("memory")
                .copied()
                .ok_or(anyhow!("not specified mem size"))?,
            m.get_one::<u32>("times")
                .copied()
                .ok_or(anyhow!("not specified iteration times"))?,
            m.get_one::<PathBuf>("secret"),
            m.get_one::<PathBuf>("associate"),
        );

        let key = read(k)?;
        let salt = match s {
            Some(f) => read(f)?,
            None => vec![],
        };
        let secret = match secret {
            Some(f) => read(f)?,
            None => vec![],
        };
        let associate = match associate {
            Some(f) => read(f)?,
            None => vec![],
        };

        let argon = match m.get_one::<String>("type").map(|x| x.as_str()) {
            Some("argon2d") => ArgonParamsBuilder::argon2d(),
            Some("argon2i") => ArgonParamsBuilder::argon2i(),
            Some("argon2id") => ArgonParamsBuilder::argon2id(),
            x => anyhow::bail!("not valid argon2 type: {:?}", x),
        };

        let argon = argon
            .degree_of_parallelism(p)
            .tag_len(tag)
            .mem_size(mem)
            .number_of_passes(times)
            .build_with_secret_associated(secret, associate)?
            .argon2(key, salt)?;

        Ok(Box::new(argon))
    }
}
