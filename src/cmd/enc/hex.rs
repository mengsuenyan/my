//! 字节串转换为Hex串
//!

use crate::cmd::Cmd;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::PathBuf;

#[derive(Clone, Default)]
pub struct HexCmd {
    pipe_data: String,
}

impl HexCmd {
    pub fn new(pipe_data: String) -> Self {
        Self { pipe_data }
    }
}

impl Cmd for HexCmd {
    const NAME: &'static str = "hex";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("Convert a byte string convert to hex string")
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
                    .help("To specified the file that need to convert to hex string")
            )
            .arg(
                Arg::new("output")
                    .value_name("FILE")
                    .long("output")
                    .short('o')
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("To specified the file to save the hex string that include PIPE,STRING,FILE hex string")
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
                Arg::new("0x")
                    .long("0x")
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("Output hex string with prefix `0x`")
            )
            .arg(
                Arg::new("endian")
                    .long("little-endian")
                    .short('l')
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("Convert byte to hex with the little-endian, default is the big-endian")
            )
            .arg(
                Arg::new("reverse")
                    .long("reverse")
                    .short('r')
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("Convert byte string from the end to start")
            )
    }

    fn run(&self, m: &ArgMatches) {
        let (is_0x, is_little_endian, is_reverse) = (
            m.get_flag("0x"),
            m.get_flag("endian"),
            m.get_flag("reverse"),
        );

        let (p_str, input, output) = (
            m.get_one::<String>("str"),
            m.get_one::<PathBuf>("filename"),
            m.get_one::<PathBuf>("output"),
        );

        let mut ostream: Box<dyn Write> = match output {
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

        let cvt = move |stream: &mut Box<dyn Write>, s: &[u8]| {
            if is_0x && !s.is_empty() {
                write!(stream, "0x")?;
            }

            if is_reverse {
                for &b in s.iter().rev() {
                    let b = if is_little_endian {
                        b.reverse_bits()
                    } else {
                        b
                    };
                    write!(stream, "{:02x}", b)?;
                }
            } else {
                for &b in s.iter() {
                    let b = if is_little_endian {
                        b.reverse_bits()
                    } else {
                        b
                    };
                    write!(stream, "{:02x}", b)?;
                }
            }

            Ok::<(), std::io::Error>(())
        };

        let pro_err = |x: std::io::Result<()>| {
            if let Err(e) = x {
                if ErrorKind::BrokenPipe != e.kind() {
                    panic!("{e}")
                } else {
                    log::info!("{e}");
                }
            }
        };

        if !self.pipe_data.is_empty() {
            pro_err(cvt(&mut ostream, self.pipe_data.as_bytes()));
        }

        if let Some(s) = p_str {
            pro_err(cvt(&mut ostream, s.as_bytes()));
        }

        if let Some(s) = input {
            let mut buf = vec![];
            let mut f = BufReader::new(File::open(s).unwrap());
            f.read_to_end(&mut buf).unwrap();
            pro_err(cvt(&mut ostream, buf.as_slice()));
        }

        pro_err(ostream.flush());
    }
}
