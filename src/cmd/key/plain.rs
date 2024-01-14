use crate::cmd::Cmd;
use anyhow::anyhow;
use cipher::KDF;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::{fs::read, path::PathBuf};
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

use super::write_to_file_or_stdout;

#[derive(Clone)]
pub struct PlainKDF {
    key: Vec<u8>,
}

impl PlainKDF {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl KDF for PlainKDF {
    fn max_key_size(&self) -> usize {
        usize::MAX
    }

    fn kdf(&mut self, _key_size: usize) -> Result<Vec<u8>, cipher::CipherError> {
        Ok(self.key.clone())
    }
}

#[cfg(feature = "sec-zeroize")]
impl Drop for PlainKDF {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

#[derive(Clone)]
pub struct PlainCmd;

impl Cmd for PlainCmd {
    const NAME: &'static str = "plain";
    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .about("plain file content as key")
            .arg(
                Arg::new("key")
                    .short('k')
                    .long("key")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true)
                    .help("password file"),
            )
    }

    fn run(&self, m: &clap::ArgMatches) {
        let mut kdf = self.generate_kdf(m).unwrap();
        let key = kdf.kdf(0).unwrap();
        write_to_file_or_stdout(m, key.as_slice()).unwrap();
    }
}

impl PlainCmd {
    pub fn generate_kdf(&self, m: &ArgMatches) -> anyhow::Result<Box<dyn KDF>> {
        let k = m
            .get_one::<PathBuf>("key")
            .ok_or(anyhow!("not specified the key file"))?;

        let key = read(k)?;

        Ok(Box::new(PlainKDF::new(key)))
    }
}
