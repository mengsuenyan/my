use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
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
                    .default_value("dec")
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
            .arg(
                Arg::new("inverse")
                    .help("inverse")
                    .long("inv")
                    .action(ArgAction::Set)
                    .required(false)
                    .value_parser(value_parser!(String)),
            )
            .subcommand(
                Command::new("mont2te")
                    .about("montgomery curve paramters to twisted edwards parameters, SP 800-186")
                    .arg(
                        Arg::new("A")
                            .help("curve fomrat parameter A of x")
                            .short('a')
                            .action(ArgAction::Set)
                            .required(true)
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("B")
                            .help("curve fomrat parameter B of y")
                            .short('b')
                            .action(ArgAction::Set)
                            .required(true)
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("X")
                            .help("generator point G_x")
                            .short('x')
                            .action(ArgAction::Set)
                            .required(true)
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("Y")
                            .help("generator point G_y")
                            .short('y')
                            .action(ArgAction::Set)
                            .required(true)
                            .value_parser(value_parser!(String)),
                    )
                    .arg(
                        Arg::new("reverse")
                            .help("twisted parameters to montgomery parameters")
                            .short('r')
                            .action(ArgAction::SetTrue)
                            .required(false),
                    ),
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

        // quadratic residue
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

        // inverse
        if let Some(s) = m.get_one::<String>("inverse") {
            let x = BigUint::from_str_radix(s.as_str(), radix).unwrap();
            let inv = Self::inv(&p, &x);
            println!("{}^(-1) = {} mod p", s, inv);
        }

        match m.subcommand() {
            Some(("mont2te", sm)) => Self::mont2te(&p, radix, sm),
            Some((other, _sm)) => println!("subcommand {other} not support"),
            _ => {}
        }
    }
}

impl FpCmd {
    fn inv(p: &BigUint, x: &BigUint) -> BigUint {
        let p_m2 = p - BigUint::from(2u8);
        x.modpow(&p_m2, p)
    }

    fn mont2te(p: &BigUint, radix: u32, m: &ArgMatches) {
        let (a, b, gu, gv) = (
            m.get_one::<String>("A").unwrap(),
            m.get_one::<String>("B").unwrap(),
            m.get_one::<String>("X").unwrap(),
            m.get_one::<String>("Y").unwrap(),
        );

        let (a, b, gu, gv) = (
            BigUint::from_str_radix(a.as_str(), radix).unwrap(),
            BigUint::from_str_radix(b.as_str(), radix).unwrap(),
            BigUint::from_str_radix(gu.as_str(), radix).unwrap(),
            BigUint::from_str_radix(gv.as_str(), radix).unwrap(),
        );

        if !m.get_flag("reverse") {
            let b_inv = Self::inv(p, &b);
            let te_a = ((&a + 2u8) * &b_inv) % p;
            let te_b = ((&a - 2u8) * &b_inv) % p;
            let v_inv = Self::inv(p, &gv);
            let u_1_inv = Self::inv(p, &(&gu + 1u8));
            let te_x = (&gu * v_inv) % p;
            let te_y = ((&gu - 1u8) * u_1_inv) % p;
            println!("============================================Montgomery2TwistedEdwards============================================");
            println!("a: {}", te_a);
            println!("d: {}", te_b);
            println!("G_x: {}", te_x);
            println!("G_y: {}", te_y);
            println!("=================================================================================================================");
        } else {
            let (a, d, x, y) = (a, b, gu, gv);
            let a_d = &a - &d;
            let a_d_inv = Self::inv(p, &a_d);
            let m_a = (((&a + &d) * &a_d_inv) * 2u8) % p;
            let m_b = (a_d_inv * 4u8) % p;
            let one_y = BigUint::from(1u8) - &y;
            let one_yx = &one_y * &x;
            let one_y_inv = Self::inv(p, &one_y);
            let one_yx_inv = Self::inv(p, &one_yx);
            let one_p_y = BigUint::from(1u8) + &y;
            let u = (&one_p_y * &one_y_inv) % p;
            let v = (one_p_y * one_yx_inv) % p;
            println!("============================================Montgomery2TwistedEdwards============================================");
            println!("A: {}", m_a);
            println!("B: {}", m_b);
            println!("G_u: {}", u);
            println!("G_v: {}", v);
            println!("=================================================================================================================");
        }
    }
}
