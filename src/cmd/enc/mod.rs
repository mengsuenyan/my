use clap::{Args, Subcommand};

use self::{
    base::{Base16Args, Base32Args, Base64Args},
    digit::{BinArgs, HexArgs},
};

pub mod base;
pub mod digit;

#[derive(Args)]
#[command(name = "enc")]
#[command(about = "data encode/decode command")]
pub struct EncCmd {
    #[command(subcommand)]
    enc: EncSubCmd,
}

#[derive(Subcommand)]
pub enum EncSubCmd {
    #[command(name = "b16", alias = "base16")]
    Base16(Base16Args),
    #[command(name = "b32", alias = "base32")]
    Base32(Base32Args),
    #[command(name = "b64", alias = "base64")]
    Base64(Base64Args),
    #[command(name = "hex")]
    Hex(HexArgs),
    #[command(name = "bin")]
    Bin(BinArgs),
}

impl EncCmd {
    pub fn exe(self, pipe: Option<&[u8]>) {
        match self.enc {
            EncSubCmd::Base16(a) => a.exe(pipe),
            EncSubCmd::Base32(a) => a.exe(pipe),
            EncSubCmd::Base64(a) => a.exe(pipe),
            EncSubCmd::Hex(a) => a.exe(pipe),
            EncSubCmd::Bin(a) => a.exe(pipe),
        }
    }
}
