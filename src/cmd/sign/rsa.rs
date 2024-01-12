use crate::cmd::{Cmd, HashCmd};
use cipher::rsa::{PSSSign, PSSVerify, PrivateKey, PublicKey};
use cipher::{CipherError, DefaultRand, Sign, Verify};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use num_bigint::BigUint;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

pub struct RSACmd;

impl Cmd for RSACmd {
    const NAME: &'static str = "rsa";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("rsa pss signer")
            .arg(
                Arg::new("key")
                    .action(ArgAction::Set)
                    .short('k')
                    .long("key")
                    .required(true)
                    .value_parser(value_parser!(PathBuf))
                    .help("key file path"),
            )
            .arg(
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .required(true)
                    .value_parser(value_parser!(PathBuf))
                    .action(ArgAction::Set)
                    .help("the message file path"),
            )
            .arg(
                Arg::new("prefix")
                    .long("prefix")
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .help("display prefix with `0x`"),
            )
            .arg(
                Arg::new("verify")
                    .long("verify")
                    .short('v')
                    .required(false)
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .help("the signature file path"),
            )
            .arg(
                Arg::new("output")
                    .long("output")
                    .short('o')
                    .required(false)
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .help("to specify the output file path to save the signature"),
            )
            .subcommand(HashCmd::cmd())
            .subcommand_required(true)
    }

    fn run(&self, m: &ArgMatches) {
        let key = m.get_one::<PathBuf>("key").unwrap();
        let key = File::open(key).unwrap();
        let key: serde_json::Value = serde_json::from_reader(key).unwrap();

        let Some((HashCmd::NAME, hm)) = m.subcommand() else {
            panic!("need to specify the hash function for the rsa signer");
        };

        let hasher = HashCmd::new(&[]).hasher_cmd(hm).generate_hasher().unwrap();

        let mut msg = Vec::with_capacity(1024);
        if let Some(f) = m.get_one::<PathBuf>("file") {
            let mut f = File::open(f).unwrap();
            let _len = f.read_to_end(&mut msg).unwrap();
        }

        let mut sig = Vec::with_capacity(256);
        if let Some(f) = m.get_one::<PathBuf>("verify") {
            let key: PublicKey = serde_json::from_value(key["pk"].clone()).unwrap();
            let pss = PSSVerify::new(key, hasher, None).unwrap();
            let mut f = File::open(f).unwrap();
            let _len = f.read_to_end(&mut sig).unwrap();
            match pss.verify(msg.as_slice(), sig.as_slice()) {
                Ok(()) => {
                    println!("Validation success.");
                }
                Err(CipherError::ValidateFailed(e)) => {
                    eprintln!("{e}");
                }
                Err(e) => panic!("{e}"),
            }
        } else {
            let key: PrivateKey = serde_json::from_value(key).unwrap();
            let rd = DefaultRand::default();
            let pss = PSSSign::new(key, hasher, rd, None).unwrap();
            pss.sign(msg.as_slice(), &mut sig).unwrap();
            let b = BigUint::from_bytes_be(sig.as_slice());

            if m.get_flag("prefix") {
                println!("{:#02x}", b);
            } else {
                println!("{:02x}", b);
            }

            if let Some(p) = m.get_one::<PathBuf>("output") {
                let mut f = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(p)
                    .unwrap();
                f.write_all(sig.as_slice()).unwrap();
            }
        }
    }
}
