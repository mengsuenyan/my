use clap::{Parser, Subcommand};

pub mod args;
pub mod config;
pub mod crypto;
pub mod enc;
mod fs;
pub mod git;
pub mod group;
pub mod guard;
pub mod hash;
pub mod info;
pub mod kdf;
pub mod mac;
mod sign;

pub const fn my_version() -> &'static str {
    concat!(env!("MY_VERSION_INFO"), " (", env!("MY_GIT_INFO"), ")")
}

pub const fn my_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[derive(Parser)]
#[command(name = my_name(), version = my_version())]
pub struct MyCli {
    #[arg(short, long, help = "receive data from pipe")]
    pub pipe: bool,

    #[arg(long, help = "config file path")]
    pub config: Option<String>,

    #[command(subcommand)]
    pub comand: Option<MySubCmd>,
}

#[derive(Subcommand)]
pub enum MySubCmd {
    Version,
    #[command(name = "hash", alias = "h")]
    Hash(hash::HashCmd),
    #[command(name = "enc")]
    Encode(enc::EncCmd),
    #[command(name = "git")]
    Git(git::GitCmd),
    #[command(name = "key", alias = "k")]
    KDF(Box<kdf::KDFArgs>),
    #[command(name = "mac")]
    MAC(mac::MACArgs),
    #[command(name = "crypto", alias = "c")]
    Crypto(Box<crypto::CryptoArgs>),
    Sign(sign::SignArgs),
    Group(group::GroupArgs),
    Fs(fs::FsArgs),
}
