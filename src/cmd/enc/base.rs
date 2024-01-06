use crate::cmd::Cmd;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use encode::base::{Base16, Base32, Base58, Base64};
use encode::{Decode, Encode};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

struct Base<T: Encode + Decode> {
    base: T,
}

impl<T: Encode + Decode> Base<T> {
    fn new(base: T) -> Self {
        Self { base }
    }

    fn cmd(name: &'static str) -> Command {
        Command::new(name)
            .arg(
                Arg::new("str")
                    .value_name("STRING")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(String))
                    .required(false)
                    .help("Byte string")
            )
            .arg(
                Arg::new("filename")
                    .value_name("FILE")
                    .long("file")
                    .short('f')
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("To specified the file that need to convert to base string")
            )
            .arg(
                Arg::new("output")
                    .value_name("FILE")
                    .long("output")
                    .short('o')
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("To specified the file to save the base string that include PIPE,STRING,FILE hex string")
            )
            .arg(
                Arg::new("truncate")
                    .long("truncate")
                    .short('x')
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("Is whether to truncate the output File before save the hex string")
            )
            .arg(
                Arg::new("decode")
                    .long("decode")
                    .short('d')
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("base decode")
            )
    }

    fn run(&mut self, m: &ArgMatches, pipe_data: Option<&[u8]>) {
        let (p_str, iname, oname, is_decode) = (
            m.get_one::<String>("str"),
            m.get_one::<PathBuf>("filename"),
            m.get_one::<PathBuf>("output"),
            m.get_flag("decode"),
        );

        let mut ostream: Box<dyn Write> = match oname {
            Some(x) => {
                if m.get_flag("truncate") {
                    Box::new(BufWriter::new(
                        OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(x)
                            .unwrap(),
                    ))
                } else {
                    Box::new(BufWriter::new(
                        OpenOptions::new().write(true).append(true).open(x).unwrap(),
                    ))
                }
            }
            None => Box::new(BufWriter::new(std::io::stdout().lock())),
        };

        if let Some(mut pipe_data) = pipe_data {
            self.exe_base(&mut pipe_data, &mut ostream, is_decode);
        }

        if let Some(p_str) = p_str {
            self.exe_base(&mut p_str.as_bytes(), &mut ostream, is_decode);
        }

        if let Some(name) = iname {
            let mut f = BufReader::new(File::open(name).unwrap());
            self.exe_base(&mut f, &mut ostream, is_decode);
        }
    }

    fn exe_base<R: Read, W: Write>(&mut self, istream: &mut R, ostream: &mut W, is_decode: bool) {
        let _o = if is_decode {
            self.base.decode(istream, ostream).unwrap()
        } else {
            self.base.encode(istream, ostream).unwrap()
        };
    }
}

pub struct Base16Cmd {
    pipe_data: Vec<u8>,
}

impl Base16Cmd {
    pub fn new(pipe_data: &[u8]) -> Self {
        Self {
            pipe_data: pipe_data.to_vec(),
        }
    }
}

impl Cmd for Base16Cmd {
    const NAME: &'static str = "b16";

    fn cmd() -> Command {
        Base::<Base16>::cmd(Self::NAME).about("base16")
    }

    fn run(&self, m: &ArgMatches) {
        let mut base = Base::new(Base16::new());

        base.run(m, Some(self.pipe_data.as_slice()));
    }
}

pub struct Base32Cmd {
    pipe_data: Vec<u8>,
}

impl Base32Cmd {
    pub fn new(pipe_data: &[u8]) -> Self {
        Self {
            pipe_data: pipe_data.to_vec(),
        }
    }
}

impl Cmd for Base32Cmd {
    const NAME: &'static str = "b32";

    fn cmd() -> Command {
        Base::<Base32>::cmd(Self::NAME).about("base32").arg(
            Arg::new("url")
                .long("url")
                .action(ArgAction::SetTrue)
                .required(false)
                .help("use base32 url code table"),
        )
    }

    fn run(&self, m: &ArgMatches) {
        let mut base = Base::new(Base32::new(!m.get_flag("url")));

        base.run(m, Some(self.pipe_data.as_slice()));
    }
}

pub struct Base64Cmd {
    pipe_data: Vec<u8>,
}

impl Base64Cmd {
    pub fn new(pipe_data: &[u8]) -> Self {
        Self {
            pipe_data: pipe_data.to_vec(),
        }
    }
}

impl Cmd for Base64Cmd {
    const NAME: &'static str = "b64";

    fn cmd() -> Command {
        Base::<Base64>::cmd(Self::NAME).about("base64").arg(
            Arg::new("url")
                .long("url")
                .action(ArgAction::SetTrue)
                .required(false)
                .help("use base32 url code table"),
        )
    }

    fn run(&self, m: &ArgMatches) {
        let mut base = Base::new(Base64::new(!m.get_flag("url")));

        base.run(m, Some(self.pipe_data.as_slice()));
    }
}

pub struct Base58Cmd {
    pipe_data: Vec<u8>,
}

impl Base58Cmd {
    pub fn new(pipe_data: &[u8]) -> Self {
        Self {
            pipe_data: pipe_data.to_vec(),
        }
    }
}

impl Cmd for Base58Cmd {
    const NAME: &'static str = "b58";

    fn cmd() -> Command {
        Base::<Base58>::cmd(Self::NAME).about("base58")
    }

    fn run(&self, m: &ArgMatches) {
        let mut base = Base::new(Base58::new());

        base.run(m, Some(self.pipe_data.as_slice()));
    }
}
