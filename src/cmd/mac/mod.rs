use clap::{Args, Subcommand};
use num_bigint::BigUint;
use std::io::Write;

use self::cmac::CMACArgs;
use self::hmac::HMACArgs;
use super::hash::{HashSubCmd, KMACXofArgs};

pub mod cmac;
pub mod hmac;

#[derive(Subcommand)]
pub enum MACSubArgs {
    #[command(name = "hmac", alias = "HMAC")]
    #[command(about = "HMAC")]
    HMAC(HMACArgs),
    #[command(name = "cmac", alias = "CMAC")]
    CMAC(CMACArgs),
    #[command(name = "kmacxof128", alias = "KMACXoF128", about = "KMACXoF128")]
    KMACXof128(KMACXofArgs),
    #[command(name = "kmacxof256", alias = "KMACXof256", about = "KMACXof256")]
    KMACXof256(KMACXofArgs),
    #[command(name = "kmac128", alias = "KMAC128", about = "KMAC128")]
    KMAC128(KMACXofArgs),
    #[command(name = "kmac256", alias = "KMAC256", about = "KMAC256")]
    KMAC256(KMACXofArgs),
}

#[derive(Args)]
#[command(about = "message authtication code")]
pub struct MACArgs {
    #[command(subcommand)]
    m: MACSubArgs,

    #[arg(long = "0x", help = "display hex format with prefix 0x")]
    prefix: bool,
}

impl MACSubArgs {
    pub fn run(self, pipe: Option<&[u8]>) -> anyhow::Result<Vec<u8>> {
        let t = [pipe.unwrap_or(&[])];
        let ipipe = Some(t.iter());
        match self {
            MACSubArgs::HMAC(m) => m.run(pipe),
            MACSubArgs::KMACXof128(a) => Ok(HashSubCmd::KMACXof128(a).run(ipipe)),
            MACSubArgs::KMACXof256(a) => Ok(HashSubCmd::KMACXof256(a).run(ipipe)),
            MACSubArgs::KMAC128(a) => Ok(HashSubCmd::KMAC128(a).run(ipipe)),
            MACSubArgs::KMAC256(a) => Ok(HashSubCmd::KMAC256(a).run(ipipe)),
            MACSubArgs::CMAC(a) => a.run(pipe),
        }
    }
}

impl MACArgs {
    pub fn exe(self, pipe: Option<&[u8]>) {
        let mac = self.m.run(pipe).unwrap();

        if self.prefix {
            let m = BigUint::from_bytes_be(&mac);
            println!("{:#02x}", m);
        } else {
            std::io::stdout().lock().write_all(&mac).unwrap()
        }
    }
}
