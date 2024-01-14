use crate::cmd::{Cmd, HashCmd};
use cipher::{
    rsa::{OAEPDecrypt, OAEPEncrypt, PKCS1Decrypt, PKCS1Encrypt, PrivateKey, PublicKey},
    stream_cipher::{
        OAEPDecryptStream, OAEPEncryptStream, PKCS1DecryptStream, PKCS1EncryptStream, StreamEncrypt,
    },
    DefaultRand, StreamDecrypt,
};
use clap::{value_parser, Arg, ArgAction, Command};
use std::path::PathBuf;

#[derive(Clone)]
pub struct RSACmd;
pub struct OAEPCmd;
pub struct PKCS1Cmd;

impl Cmd for PKCS1Cmd {
    const NAME: &'static str = "pkcs1";
    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .about("PKCS #1 v1.5 Public Key Cryptography Standards v1.5")
            .arg(
                Arg::new("msg")
                    .value_name("MESSAGE")
                    .required(false)
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(String))
                    .help("to specify the message"),
            )
            .arg(
                Arg::new("key")
                    .short('k')
                    .long("key")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true)
                    .help("to specify the key file path"),
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
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("to specify the file path"),
            )
            .arg(
                Arg::new("decrypt")
                    .short('d')
                    .long("is-decrypt")
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("the flag to decrypt all files or message"),
            )
    }
    fn run(&self, m: &clap::ArgMatches) {
        let (key, file, output, msg) = (
            m.get_one::<PathBuf>("key").cloned().unwrap(),
            m.get_one::<PathBuf>("file"),
            m.get_one::<PathBuf>("output"),
            m.get_one::<String>("msg"),
        );

        let key = std::fs::read(key).unwrap();
        let key: serde_json::Value = serde_json::from_slice(key.as_slice()).unwrap();
        let rng = DefaultRand::default();
        if m.get_flag("decrypt") {
            let key: PrivateKey = serde_json::from_value(key).unwrap();
            let pkcs = PKCS1Decrypt::new(key, rng).unwrap();
            let mut pkcs = PKCS1DecryptStream::from(pkcs);

            if let Some(msg) = msg {
                let (mut msg, mut buf) = (msg.as_bytes(), Vec::with_capacity(1024));
                let finish = pkcs.stream_decrypt(&mut msg, &mut buf).unwrap();
                finish.finish(&mut buf).unwrap();
                for x in buf {
                    print!("{:02x}", x);
                }
                println!();
            }

            if let Some((file, output)) = file.zip(output) {
                let data = std::fs::read(file).unwrap();
                let (mut data, mut buf) = (data.as_slice(), Vec::with_capacity(1024));
                let finish = pkcs.stream_decrypt(&mut data, &mut buf).unwrap();
                finish.finish(&mut buf).unwrap();
                std::fs::write(output, buf).unwrap();
            }
        } else {
            let key: PublicKey = serde_json::from_value(key["pk"].clone()).unwrap();
            let pkcs = PKCS1Encrypt::new(key, rng).unwrap();
            let mut pkcs = PKCS1EncryptStream::from(pkcs);

            if let Some(msg) = msg {
                let (mut msg, mut buf) = (msg.as_bytes(), Vec::with_capacity(1024));
                let finish = pkcs.stream_encrypt(&mut msg, &mut buf).unwrap();
                finish.finish(&mut buf).unwrap();
                for x in buf {
                    print!("{:02x}", x);
                }
                println!();
            }

            if let Some((file, output)) = file.zip(output) {
                let data = std::fs::read(file).unwrap();
                let (mut data, mut buf) = (data.as_slice(), Vec::with_capacity(1024));
                let finish = pkcs.stream_encrypt(&mut data, &mut buf).unwrap();
                finish.finish(&mut buf).unwrap();
                std::fs::write(output, buf).unwrap();
            }
        }
    }
}

impl Cmd for OAEPCmd {
    const NAME: &'static str = "oaep";
    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("PKCS #1 v2.2 Optimal Asymmetric Encryption Padding")
            .subcommand_required(true)
            .arg(
                Arg::new("msg")
                    .value_name("MESSAGE")
                    .required(false)
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(String))
                    .help("to specify the message"),
            )
            .arg(
                Arg::new("key")
                    .short('k')
                    .long("key")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true)
                    .help("to specify the key file path"),
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
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("to specify the file path"),
            )
            .arg(
                Arg::new("decrypt")
                    .short('d')
                    .long("is-decrypt")
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("the flag to decrypt all files or message"),
            )
            .arg(
                Arg::new("label")
                    .long("label")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("to specify the label content for the OAEP"),
            )
            .subcommand(HashCmd::cmd())
    }
    fn run(&self, m: &clap::ArgMatches) {
        let Some((HashCmd::NAME, hm)) = m.subcommand() else {
            panic!("The RSA OAEP need to specified the hash function");
        };
        let (key, file, output, msg, label) = (
            m.get_one::<PathBuf>("key").cloned().unwrap(),
            m.get_one::<PathBuf>("file"),
            m.get_one::<PathBuf>("output"),
            m.get_one::<String>("msg"),
            m.get_one::<PathBuf>("label"),
        );

        let hasher = HashCmd::new(&[]).hasher_cmd(hm).generate_hasher().unwrap();
        let rng = DefaultRand::default();
        let label = if let Some(label) = label {
            std::fs::read(label).unwrap()
        } else {
            vec![]
        };

        let key = std::fs::read(key).unwrap();
        let key: serde_json::Value = serde_json::from_slice(key.as_slice()).unwrap();
        if m.get_flag("decrypt") {
            let key: PrivateKey = serde_json::from_value(key).unwrap();
            let oaep = OAEPDecrypt::new(key, hasher, rng, label.as_slice()).unwrap();
            let mut oaep = OAEPDecryptStream::from(oaep);

            if let Some(msg) = msg {
                let (mut msg, mut buf) = (msg.as_bytes(), Vec::with_capacity(1024));
                let finish = oaep.stream_decrypt(&mut msg, &mut buf).unwrap();
                finish.finish(&mut buf).unwrap();
                for x in buf {
                    print!("{:02x}", x);
                }
                println!();
            }

            if let Some((file, output)) = file.zip(output) {
                let data = std::fs::read(file).unwrap();
                let (mut data, mut buf) = (data.as_slice(), Vec::with_capacity(1024));
                let finish = oaep.stream_decrypt(&mut data, &mut buf).unwrap();
                finish.finish(&mut buf).unwrap();
                std::fs::write(output, buf).unwrap();
            }
        } else {
            let key: PublicKey = serde_json::from_value(key["pk"].clone()).unwrap();
            let oaep = OAEPEncrypt::new(key, hasher, rng, label.as_slice()).unwrap();
            let mut oaep = OAEPEncryptStream::from(oaep);

            if let Some(msg) = msg {
                let (mut msg, mut buf) = (msg.as_bytes(), Vec::with_capacity(1024));
                let finish = oaep.stream_encrypt(&mut msg, &mut buf).unwrap();
                finish.finish(&mut buf).unwrap();
                for x in buf {
                    print!("{:02x}", x);
                }
                println!();
            }

            if let Some((file, output)) = file.zip(output) {
                let data = std::fs::read(file).unwrap();
                let (mut data, mut buf) = (data.as_slice(), Vec::with_capacity(1024));
                let finish = oaep.stream_encrypt(&mut data, &mut buf).unwrap();
                finish.finish(&mut buf).unwrap();
                std::fs::write(output, buf).unwrap();
            }
        }
    }
}

impl Cmd for RSACmd {
    const NAME: &'static str = "rsa";
    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("cipher base on the RSA algorithm")
            .subcommand_required(true)
            .subcommand(PKCS1Cmd::cmd())
            .subcommand(OAEPCmd::cmd())
    }
    fn run(&self, m: &clap::ArgMatches) {
        match m.subcommand() {
            Some((PKCS1Cmd::NAME, m)) => PKCS1Cmd.run(m),
            Some((OAEPCmd::NAME, m)) => OAEPCmd.run(m),
            Some((n, _m)) => panic!("unsupport subcommand {n}"),
            _ => unreachable!(),
        }
    }
}
