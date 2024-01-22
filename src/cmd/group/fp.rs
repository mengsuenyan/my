use clap::{value_parser, Arg, ArgAction, Command};
use num_bigint::BigUint;
use num_traits::{Num, One};

use crate::cmd::Cmd;

#[derive(Clone)]
pub struct FpCmd;

impl Cmd for FpCmd {
    const NAME: &'static str = "fp";
    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .about("prime field")
            .arg(
                Arg::new("mod")
                    .help("prime number")
                    .value_name("MODULUS")
                    .action(ArgAction::Set)
                    .required(true)
                    .value_parser(value_parser!(String)),
            )
            .arg(
                Arg::new("type")
                    .help("the bigint number string type")
                    .action(ArgAction::Set)
                    .short('t')
                    .long("type")
                    .default_value("hex")
                    .required(false)
                    .value_parser(["hex", "dec", "bin", "oct"]),
            )
            .arg(
                Arg::new("qresidue")
                    .help("quadratic residue decision")
                    .long("qresidue")
                    .action(ArgAction::Set)
                    .required(false)
                    .value_parser(value_parser!(String)),
            )
    }

    fn run(&self, m: &clap::ArgMatches) {
        let radix = match m.get_one::<String>("type").unwrap().as_str() {
            "hex" => 16,
            "bin" => 2,
            "dec" => 10,
            "oct" => 8,
            _ => unreachable!(),
        };

        let p = m.get_one::<String>("mod").unwrap();
        let p = BigUint::from_str_radix(p.as_str(), radix).unwrap();

        if let Some(qresidue) = m.get_one::<String>("qresidue") {
            let n = BigUint::from_str_radix(qresidue.as_str(), radix).unwrap();
            let neg_one = &p - 1u8;
            let n = n.modpow(&((&p - 1u8) / 2u8), &p);
            if n.is_one() {
                println!("{qresidue} is quadratic residue");
            } else if n == neg_one {
                println!("{qresidue} is quadratic non-residue");
            } else {
                println!("cannot to decide {qresidue}");
            }
        }
    }
}
