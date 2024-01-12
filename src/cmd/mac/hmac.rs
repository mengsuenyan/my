use crate::cmd::{Cmd, HashCmd};
use cipher::{prf::HMAC, MAC};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use crypto_hash::DigestX;
use num_bigint::BigUint;
use std::{io::Write, path::PathBuf};

#[derive(Clone)]
pub struct HMACCmd;

impl Cmd for HMACCmd {
    const NAME: &'static str = "hmac";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("HMAC")
            .arg(
                Arg::new("msg")
                    .value_name("MESSAGE")
                    .action(ArgAction::Set)
                    .required(false)
                    .value_parser(value_parser!(String))
                    .help("the message that need to authentication"),
            )
            .arg(
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .required(false)
                    .value_parser(value_parser!(PathBuf))
                    .help("the file that need to authentication"),
            )
            .arg(
                Arg::new("key")
                    .action(ArgAction::Set)
                    .short('k')
                    .long("key")
                    .required(true)
                    .value_parser(value_parser!(PathBuf))
                    .help("key file path"),
            )
            .subcommand(HashCmd::cmd())
            .subcommand_required(true)
    }

    fn run(&self, m: &ArgMatches) {
        let msg = m
            .get_one::<String>("msg")
            .map(|x| x.as_bytes().to_vec())
            .unwrap_or_default();
        let content = if let Some(p) = m.get_one::<PathBuf>("file") {
            std::fs::read(p).unwrap()
        } else {
            vec![]
        };

        let mut hmac = self.generate_hmac(m).unwrap();
        hmac.write_all(&msg).unwrap();
        hmac.write_all(&content).unwrap();
        let mac = BigUint::from_bytes_be(hmac.mac().as_slice());
        println!("{:x}", mac);
    }
}

impl HMACCmd {
    pub fn generate_hmac(&self, m: &ArgMatches) -> anyhow::Result<HMAC<Box<dyn DigestX>>> {
        let Some((HashCmd::NAME, hm)) = m.subcommand() else {
            anyhow::bail!("need to specification hash function")
        };

        let hasher = HashCmd::new(&[]).hasher_cmd(hm).generate_hasher()?;

        let key = std::fs::read(m.get_one::<PathBuf>("key").unwrap())?;

        Ok(HMAC::new(hasher, key)?)
    }
}
