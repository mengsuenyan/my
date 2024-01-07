use crate::cmd::Cmd;
use cipher::rsa::PrivateKey;
use cipher::DefaultRand;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

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

        let mut out: Box<dyn Write> = match m.get_one::<PathBuf>("output") {
            Some(p) => {
                let f = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(p)
                    .unwrap();
                Box::new(f)
            }
            None => Box::new(std::io::stdout().lock()),
        };

        let mut rng = DefaultRand::default();
        let key = PrivateKey::generate_multi_prime_key(primes, bits, rounds, &mut rng).unwrap();
        let key = serde_json::to_string_pretty(&key).unwrap();
        out.write_all(key.as_bytes()).unwrap();
    }
}
