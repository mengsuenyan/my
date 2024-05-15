use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use cipher::{rsa::PrivateKey, DefaultRand};
use clap::{value_parser, Args};

use crate::cmd::args::Key;

#[derive(Args, Clone)]
#[command(about = "RSA private key generate")]
pub struct RSAArgs {
    #[arg(value_name = "BITs", default_value = "2048")]
    #[arg(help = "the public key modulus bits length")]
    bits: usize,

    #[arg(short, long, default_value = "2", value_parser = value_parser!(u32).range(2..))]
    #[arg(help = "the public key modulus prime factor numbers")]
    primes: u32,

    #[arg(short, long, default_value = "19", value_parser = value_parser!(u32).range(1..))]
    #[arg(help = "the provable prime test rounds")]
    test: u32,

    #[arg(
        short,
        long,
        help = r#"file to save private key, it will output to stdout if not specified
the private key is convert to json data by the serde"#
    )]
    ofile: Option<PathBuf>,

    #[arg(long, help = "force write if the oflile already exists")]
    force: bool,

    #[arg(long = "0x", help = "display with prefix 0x")]
    prefix: bool,
}

impl RSAArgs {
    pub fn run(&self) -> anyhow::Result<Key> {
        let mut rng = DefaultRand::default();

        let pk = PrivateKey::generate_multi_prime_key(
            self.primes as usize,
            self.bits,
            self.test as usize,
            &mut rng,
        )?;

        let v = if self.prefix {
            pk.to_string().into_bytes()
        } else {
            serde_json::to_vec(&pk)?
        };
        Ok(Key::new(v))
    }

    pub fn exe(self) {
        let key = self.run().unwrap();

        if let Some(f) = self.ofile {
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create_new(!(self.force && f.is_file()))
                .open(f)
                .unwrap();
            file.write_all(key.as_ref()).unwrap();
        } else {
            std::io::stdout().lock().write_all(key.as_ref()).unwrap();
        }
    }

    pub(super) fn set_ksize(&mut self, ksize: usize) {
        self.bits = ksize << 3;
    }
}
