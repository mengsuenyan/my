use std::io::{Read, Write};

use clap::Args;
use encode::{
    base::{Base16, Base32, Base64},
    Decode, Encode,
};

use crate::cmd::{args::IOArgs, config::MyConfig};

#[derive(Args)]
pub struct BaseArgs {
    #[arg(value_name = "STRING", allow_hyphen_values = true)]
    pub str: Option<String>,

    #[command(flatten)]
    pub io: IOArgs,

    #[arg(short, long)]
    pub decode: bool,
}

#[derive(Args)]
#[command(about = "base16(PIPE | STRING | file)")]
pub struct Base16Args {
    #[command(flatten)]
    b16: BaseArgs,
}

#[derive(Args)]
#[command(about = "base32(PIPE | STRING | file)")]
pub struct Base32Args {
    #[command(flatten)]
    b32: BaseArgs,

    #[arg(long)]
    #[arg(help = "use base32 url code table")]
    url: bool,
}

#[derive(Args)]
#[command(about = "base64(PIPE | STRING | file)")]
pub struct Base64Args {
    #[command(flatten)]
    b64: BaseArgs,

    #[arg(long)]
    #[arg(help = "use base32 url code table")]
    url: bool,
}

impl BaseArgs {
    pub fn exe<T: Encode + Decode>(self, mut b: T, pipe: Option<&[u8]>) {
        let file_data = self.io.read_all_data().unwrap();

        let mut ostream = self
            .io
            .writer_with_default(MyConfig::config().io_buf_size)
            .unwrap();

        if let Some(data) = pipe {
            self.exe_inner(&mut b, data, &mut ostream)
        }

        if let Some(data) = self.str.as_deref() {
            self.exe_inner(&mut b, data.as_bytes(), &mut ostream);
        }

        if let Some(data) = file_data.as_deref() {
            self.exe_inner(&mut b, data, &mut ostream);
        }
    }

    fn exe_inner<T: Encode + Decode, R: Read, W: Write>(
        &self,
        b: &mut T,
        mut istream: R,
        ostream: &mut W,
    ) {
        if self.decode {
            let _ = b.decode(&mut istream, ostream).unwrap();
        } else {
            let _ = b.encode(&mut istream, ostream).unwrap();
        }
    }
}

impl Base16Args {
    pub fn exe(self, pipe: Option<&[u8]>) {
        self.b16.exe(Base16::new(), pipe);
    }
}

impl Base32Args {
    pub fn exe(self, pipe: Option<&[u8]>) {
        let is_std = !self.url;
        self.b32.exe(Base32::new(is_std), pipe);
    }
}

impl Base64Args {
    pub fn exe(self, pipe: Option<&[u8]>) {
        let is_std = !self.url;

        self.b64.exe(Base64::new(is_std), pipe);
    }
}
