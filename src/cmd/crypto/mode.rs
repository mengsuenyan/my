use anyhow::Result;
use cipher::{
    cipher_mode::{CBCCs, CBCCsMode, DefaultCounter, DefaultPadding, CBC, CFB, CTR, ECB, OFB},
    BlockCipherX, BlockEncryptX, Cipher,
};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::{ops::Range, path::PathBuf, sync::Mutex};

use crate::cmd::Cmd;

use super::{common_crypto, AES128Cmd, AES192Cmd, AES256Cmd, SM4Cmd};

pub fn common_command(name: &'static str) -> Command {
    Command::new(name)
        .subcommand_required(true)
        .subcommand(SM4Cmd::cmd())
        .subcommand(AES128Cmd::cmd())
        .subcommand(AES192Cmd::cmd())
        .subcommand(AES256Cmd::cmd())
}

pub fn common_run<'a>(
    name: &str,
    m: &'a ArgMatches,
) -> Result<(Vec<Box<dyn BlockCipherX + Send + Sync>>, &'a ArgMatches)> {
    let Some((block, bm)) = m.subcommand() else {
        anyhow::bail!("need to specify the block cipher for {}", name);
    };

    let bc = match block {
        SM4Cmd::NAME => SM4Cmd.generate_block_cipher(bm).unwrap(),
        AES128Cmd::NAME => AES128Cmd.generate_block_cipher(bm).unwrap(),
        AES192Cmd::NAME => AES192Cmd.generate_block_cipher(bm).unwrap(),
        AES256Cmd::NAME => AES256Cmd.generate_block_cipher(bm).unwrap(),
        name => anyhow::bail!("not support the {}", name),
    };

    Ok((bc, bm))
}

macro_rules! def_cipher_mode_cmd {
    ($NAME: ident) => {
        #[derive(Clone)]
        pub struct $NAME;
    };
    ($NAME1:  ident, $($NAME2: ident),+) => {
        def_cipher_mode_cmd!($NAME1);
        def_cipher_mode_cmd!($($NAME2),+);
    }
}

def_cipher_mode_cmd!(ECBCmd, CBCCmd, CFBCmd, OFBCmd, CTRCmd, CBCsCmd);

impl Cmd for ECBCmd {
    const NAME: &'static str = "ecb";
    fn cmd() -> clap::Command {
        common_command(Self::NAME)
            .about("electronic codebook mode")
            .arg(
                Arg::new("padding")
                    .long("padding")
                    .required(false)
                    .action(ArgAction::Set)
                    .default_value("default")
                    .value_parser(["default"])
                    .help("padding method"),
            )
    }
    fn run(&self, m: &clap::ArgMatches) {
        let (bc, bm) = common_run(Self::NAME, m).unwrap();

        let mut ecb: Vec<Box<dyn Cipher + Send + Sync>> = Vec::with_capacity(bc.len());
        for bc in bc {
            let x: Box<dyn Cipher + Send + Sync> =
                Box::new(Mutex::new(ECB::<DefaultPadding, _>::new(bc)));
            ecb.push(x);
        }

        common_crypto(ecb, bm).unwrap()
    }
}

impl Cmd for CBCCmd {
    const NAME: &'static str = "cbc";
    fn cmd() -> Command {
        common_command(Self::NAME)
            .about("cipher block chaining mode")
            .arg(
                Arg::new("padding")
                    .long("padding")
                    .required(false)
                    .action(ArgAction::Set)
                    .default_value("default")
                    .value_parser(["default"])
                    .help("padding method"),
            )
            .arg(
                Arg::new("iv")
                    .help("initial vector that length must eqaul to block size")
                    .long("iv")
                    .required(true)
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf)),
            )
    }

    fn run(&self, m: &ArgMatches) {
        let iv = m.get_one::<PathBuf>("iv").unwrap();
        let iv = std::fs::read(iv).unwrap();

        let (bc, bm) = common_run(Self::NAME, m).unwrap();

        let mut cbc: Vec<Box<dyn Cipher + Send + Sync>> = Vec::with_capacity(bc.len());
        for bc in bc {
            let x: Box<dyn Cipher + Send + Sync> = Box::new(Mutex::new(
                CBC::<DefaultPadding, _>::new(bc, iv.clone()).unwrap(),
            ));
            cbc.push(x);
        }

        common_crypto(cbc, bm).unwrap()
    }
}

impl Cmd for CFBCmd {
    const NAME: &'static str = "cfb";
    fn cmd() -> Command {
        common_command(Self::NAME)
            .about("cipher feedback mode")
            .arg(
                Arg::new("padding")
                    .long("padding")
                    .required(false)
                    .action(ArgAction::Set)
                    .default_value("default")
                    .value_parser(["default"])
                    .help("padding method"),
            )
            .arg(
                Arg::new("iv")
                    .help("initial vector that length must eqaul to block size")
                    .long("iv")
                    .required(true)
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                Arg::new("bytes")
                    .help("the CFB s parameter that need to less than or equal to block size")
                    .long("bytes")
                    .default_value("16")
                    .required(true)
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(usize)),
            )
    }

    fn run(&self, m: &ArgMatches) {
        let s = m.get_one::<usize>("bytes").copied().unwrap();
        let iv = m.get_one::<PathBuf>("iv").unwrap();
        let iv = std::fs::read(iv).unwrap();

        let (bc, bm) = common_run(Self::NAME, m).unwrap();

        let mut cfb: Vec<Box<dyn Cipher + Send + Sync>> = Vec::with_capacity(bc.len());
        for bc in bc {
            let x: Box<dyn Cipher + Send + Sync> = Box::new(Mutex::new(
                CFB::<DefaultPadding, _>::new(bc, iv.clone(), s).unwrap(),
            ));
            cfb.push(x);
        }

        common_crypto(cfb, bm).unwrap()
    }
}

impl Cmd for OFBCmd {
    const NAME: &'static str = "ofb";
    fn cmd() -> Command {
        common_command(Self::NAME)
            .about("output feedback mode")
            .arg(
                Arg::new("iv")
                    .help("initial vector that length must eqaul to block size")
                    .long("iv")
                    .required(true)
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf)),
            )
    }

    fn run(&self, m: &ArgMatches) {
        let iv = m.get_one::<PathBuf>("iv").unwrap();
        let iv = std::fs::read(iv).unwrap();

        let (bc, bm) = common_run(Self::NAME, m).unwrap();

        let mut ofb: Vec<Box<dyn Cipher + Send + Sync>> = Vec::with_capacity(bc.len());
        for bc in bc {
            let x: Box<dyn Cipher + Send + Sync> =
                Box::new(Mutex::new(OFB::new(bc, iv.clone()).unwrap()));
            ofb.push(x);
        }

        common_crypto(ofb, bm).unwrap()
    }
}

impl Cmd for CTRCmd {
    const NAME: &'static str = "ctr";
    fn cmd() -> Command {
        common_command(Self::NAME)
            .about("counter mode")
            .arg(
                Arg::new("iv")
                    .help("initial vector that length must eqaul to block size")
                    .long("iv")
                    .required(true)
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf)),
            )
            .arg(
                Arg::new("counter")
                    .help("counter type")
                    .long("counter")
                    .required(false)
                    .default_value("default")
                    .action(ArgAction::Set)
                    .value_parser(["default"]),
            )
    }
    fn run(&self, m: &ArgMatches) {
        let iv = m.get_one::<PathBuf>("iv").unwrap();
        let iv = std::fs::read(iv).unwrap();

        let (bc, bm) = common_run(Self::NAME, m).unwrap();
        let counter = DefaultCounter::new(
            iv,
            Range {
                start: 0,
                end: BlockEncryptX::block_size_x(&bc[0]),
            },
        )
        .unwrap();

        let mut ctr: Vec<Box<dyn Cipher + Send + Sync>> = Vec::with_capacity(bc.len());
        for bc in bc {
            let x: Box<dyn Cipher + Send + Sync> =
                Box::new(Mutex::new(CTR::new(bc, counter.clone()).unwrap()));
            ctr.push(x);
        }

        common_crypto(ctr, bm).unwrap()
    }
}

impl Cmd for CBCsCmd {
    const NAME: &'static str = "cbcs";
    fn cmd() -> Command {
        common_command(Self::NAME)
        .about("cipher block chaining-ciphertext stealing. Note: the data size need to great than block size")
        .arg(
            Arg::new("iv")
            .help("initial vector that length must eqaul to block size")
            .long("iv")
            .required(true)
            .action(ArgAction::Set)
            .value_parser(value_parser!(PathBuf))
        )
        .arg(
            Arg::new("mode")
            .help("to specify the CBC work mode")
            .long("mode")
            .required(true)
            .default_value("cbcs1")
            .value_parser(["cbcs1", "cbcs2", "cbcs3"])
            .action(ArgAction::Set)
        )
    }

    fn run(&self, m: &ArgMatches) {
        let iv = m.get_one::<PathBuf>("iv").unwrap();
        let iv = std::fs::read(iv).unwrap();

        let mode = match m.get_one::<String>("mode").unwrap().as_str() {
            "cbcs1" => CBCCsMode::CbcCs1,
            "cbcs2" => CBCCsMode::CbcCs2,
            "cbcs3" => CBCCsMode::CbcCs3,
            m => unreachable!("not support the CBCsMode: {}", m),
        };

        let (bc, bm) = common_run(Self::NAME, m).unwrap();

        let mut cbcs: Vec<Box<dyn Cipher + Send + Sync>> = Vec::with_capacity(bc.len());
        for bc in bc {
            let x: Box<dyn Cipher + Send + Sync> =
                Box::new(Mutex::new(CBCCs::new(bc, iv.clone(), mode).unwrap()));
            cbcs.push(x);
        }

        common_crypto(cbcs, bm).unwrap()
    }
}
