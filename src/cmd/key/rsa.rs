use crate::cmd::Cmd;
use cipher::rsa::PrivateKey;
use cipher::DefaultRand;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::path::PathBuf;

use super::write_to_file_or_stdout;

#[derive(Default)]
pub struct RSACmd;

impl Cmd for RSACmd {
    const NAME: &'static str = "rsa";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("rsa key generate")
            .arg(
                Arg::new("bits")
                    .value_name("BITS")
                    .action(ArgAction::Set)
                    .required(true)
                    .value_parser(value_parser!(usize))
                    .help("to specify the public key modulus bits length"),
            )
            .arg(
                Arg::new("primes")
                    .long("primes")
                    .short('p')
                    .action(ArgAction::Set)
                    .default_value("2")
                    .required(false)
                    .value_parser(value_parser!(usize))
                    .help("to specify the public key modulus prime factor numbers"),
            )
            .arg(
                Arg::new("test")
                    .long("test")
                    .short('t')
                    .action(ArgAction::Set)
                    .default_value("19")
                    .required(false)
                    .value_parser(value_parser!(usize))
                    .help("to specify the provable prime test rounds"),
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
    }

    fn run(&self, m: &ArgMatches) {
        let (bits, primes, rounds) = (
            m.get_one::<usize>("bits").copied().unwrap(),
            m.get_one::<usize>("primes").copied().unwrap(),
            m.get_one::<usize>("test").copied().unwrap(),
        );

        let mut rng = DefaultRand::default();
        let key = PrivateKey::generate_multi_prime_key(primes, bits, rounds, &mut rng).unwrap();
        if m.contains_id("output") {
            let key = serde_json::to_vec(&key).unwrap();
            write_to_file_or_stdout(m, key.as_slice()).unwrap()
        } else {
            println!("{}", key);
        }
    }
}
