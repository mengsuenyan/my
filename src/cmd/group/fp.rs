use clap::{
    builder::{PossibleValuesParser, TypedValueParser},
    Args, Subcommand,
};
use num_bigint::BigUint;
use num_traits::{Num, One};

fn string_type(s: String) -> u32 {
    match s.as_str() {
        "hex" => 16,
        "bin" => 2,
        "dec" => 10,
        "oct" => 8,
        _ => unreachable!("not support string type"),
    }
}

#[derive(Args)]
#[command(about = "prime field")]
pub struct FpArgs {
    #[arg(help = "prime number(p)")]
    modulus: String,

    #[arg(short='t', long="type", value_parser = PossibleValuesParser::new(["hex", "dec", "bin", "oct"]).map(string_type))]
    #[arg(default_value = "dec", help = "the bigint number string type")]
    radix: u32,

    #[arg(long = "inv", help = "to compute inv^(-1) % p")]
    inverse: Option<String>,

    #[arg(long, help = "to determine whether it's a quadratic residue")]
    qresidue: Option<String>,

    #[command(subcommand)]
    sub_cmd: Option<FpSubArgs>,
}

#[derive(Subcommand)]
enum FpSubArgs {
    Mont2te(Mont2teArgs),
}

#[derive(Args)]
#[command(about = "montgomery curve parameters to twisted edwards parameters, NIST SP 800-186")]
struct Mont2teArgs {
    #[arg(
        short,
        long,
        value_name = "A/a",
        help = "curve parameter `A` of `a` of x"
    )]
    a: String,
    #[arg(
        short,
        long,
        value_name = "B/d",
        help = "curve parameter `A` of `d` of y"
    )]
    b: String,
    #[arg(
        short,
        long,
        value_name = "Gu/Gx",
        help = "generator point `G_u` or `G_x`"
    )]
    gu: String,
    #[arg(
        short,
        long,
        value_name = "Gv/Gy",
        help = "generator point `G_v` or `G_y`"
    )]
    gv: String,
    #[arg(
        short,
        long,
        help = "twisted edwards parameters to montgomery curve parameters"
    )]
    reverse: bool,
}

impl FpArgs {
    fn inv(p: &BigUint, x: &BigUint) -> BigUint {
        let p_m2 = p - BigUint::from(2u8);
        x.modpow(&p_m2, p)
    }

    pub fn exe(self) {
        let p = BigUint::from_str_radix(self.modulus.as_str(), self.radix).unwrap();

        if let Some(qresidue) = self.qresidue {
            let n = BigUint::from_str_radix(qresidue.as_str(), self.radix).unwrap();
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

        if let Some(s) = self.inverse {
            let x = BigUint::from_str_radix(s.as_str(), self.radix).unwrap();
            let inv = Self::inv(&p, &x);
            println!("{}^(-1) = {} mod p", s, inv);
        }

        if let Some(sub_cmd) = self.sub_cmd {
            match sub_cmd {
                FpSubArgs::Mont2te(a) => a.exe(&p, self.radix),
            }
        }
    }
}

impl Mont2teArgs {
    fn exe(self, p: &BigUint, radix: u32) {
        let (a, b, gu, gv) = (
            BigUint::from_str_radix(self.a.as_str(), radix).unwrap(),
            BigUint::from_str_radix(self.b.as_str(), radix).unwrap(),
            BigUint::from_str_radix(self.gu.as_str(), radix).unwrap(),
            BigUint::from_str_radix(self.gv.as_str(), radix).unwrap(),
        );

        if !self.reverse {
            let b_inv = FpArgs::inv(p, &b);
            let te_a = ((&a + 2u8) * &b_inv) % p;
            let te_b = ((&a + (p - 2u8)) * &b_inv) % p;
            let v_inv = FpArgs::inv(p, &gv);
            let u_1_inv = FpArgs::inv(p, &(&gu + 1u8));
            let te_x = (&gu * v_inv) % p;
            let te_y = ((&gu + (p - 1u8)) * u_1_inv) % p;
            println!("============================================Montgomery2TwistedEdwards============================================");
            println!("a: {}", te_a);
            println!("d: {}", te_b);
            println!("G_x: {}", te_x);
            println!("G_y: {}", te_y);
            println!("=================================================================================================================");
        } else {
            let (a, d, x, y) = (a, b, gu, gv);
            let a_d = (&a + (p - &d)) % p;
            let a_d_inv = FpArgs::inv(p, &a_d);
            let m_a = (((&a + &d) * &a_d_inv) * 2u8) % p;
            let m_b = (a_d_inv * 4u8) % p;
            let one_y = (BigUint::from(1u8) + (p - &y)) % p;
            let one_yx = &one_y * &x;
            let one_y_inv = FpArgs::inv(p, &one_y);
            let one_yx_inv = FpArgs::inv(p, &one_yx);
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
