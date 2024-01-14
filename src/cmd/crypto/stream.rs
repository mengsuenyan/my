use std::{path::PathBuf, sync::Mutex};

use cipher::{
    stream_cipher::zuc::{ZUCKey, ZUC},
    Cipher,
};
use clap::{value_parser, Arg, ArgAction, Command};

use super::{block, common_crypto};
use crate::cmd::Cmd;

#[derive(Clone)]
pub struct ZUCCmd;

impl Cmd for ZUCCmd {
    const NAME: &'static str = "zuc";
    fn cmd() -> clap::Command {
        let cmd = Command::new(Self::NAME).subcommand_required(true);

        block::common_subcommand(cmd)
            .about("ZUC stream cipher")
            .arg(
                Arg::new("count")
                    .long("count")
                    .action(ArgAction::Set)
                    .required(true)
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                Arg::new("bearer")
                    .long("bearer")
                    .action(ArgAction::Set)
                    .required(true)
                    .value_parser(value_parser!(u64).range(0..32)),
            )
            .arg(
                Arg::new("direction")
                    .help("direction")
                    .long("dir")
                    .action(ArgAction::Set)
                    .required(true)
                    .value_parser(["0", "1"]),
            )
    }
    fn run(&self, m: &clap::ArgMatches) {
        let (count, bearer, dir) = (
            m.get_one::<u32>("count").copied().unwrap(),
            m.get_one::<u64>("bearer").copied().unwrap() as u8,
            !matches!(m.get_one::<String>("direction").unwrap().as_str(), "0"),
        );

        let nums = (m
            .get_many::<PathBuf>("file")
            .map(|x| x.count())
            .unwrap_or_default()
            + m.get_many::<PathBuf>("output")
                .map(|x| x.count())
                .unwrap_or_default()
            + m.get_one::<String>("msg").map(|_x| 1).unwrap_or_default())
        .max(1);

        let mut kdf = block::common_run(m).unwrap();
        let key = kdf.kdf(ZUCKey::KEY_SIZE).unwrap().try_into().unwrap();

        let zuc = ZUC::new(count, bearer, dir, key);
        let mut v: Vec<Box<dyn Cipher + Send + Sync>> = Vec::with_capacity(nums);
        for _ in 0..nums {
            v.push(Box::new(Mutex::new(zuc.clone())));
        }

        common_crypto(v, m).unwrap();
    }
}
