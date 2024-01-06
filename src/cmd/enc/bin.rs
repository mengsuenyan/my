//! 字节串转换为Bin串
//!

use crate::cmd::enc::SType;
use crate::cmd::Cmd;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use num_bigint::BigInt;
use num_traits::Num;
use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::io::{Error as StdIoErr, ErrorKind as StdIoErrKind};
use std::path::PathBuf;

#[derive(Clone, Default)]
pub struct BinCmd {
    pipe_data: Vec<u8>,
    is_0b: Cell<bool>,
    is_reverse: Cell<bool>,
    is_little_endian: Cell<bool>,
    s_type: Cell<SType>,
}

impl BinCmd {
    pub fn new(pipe_data: &[u8]) -> Self {
        Self {
            pipe_data: pipe_data.to_vec(),
            is_0b: Cell::new(false),
            is_reverse: Cell::new(false),
            is_little_endian: Cell::new(false),
            s_type: Cell::new(SType::Str),
        }
    }

    fn is_0b(&self, is_set: bool) -> &Self {
        self.is_0b.set(is_set);
        self
    }

    fn is_reverse(&self, is_set: bool) -> &Self {
        self.is_reverse.set(is_set);
        self
    }

    fn is_little_endian(&self, is_set: bool) -> &Self {
        self.is_little_endian.set(is_set);
        self
    }

    fn s_type(&self, s_type: SType) -> &Self {
        self.s_type.set(s_type);
        self
    }

    fn cvt_str(&self, stream: &mut Box<dyn Write>, s: &[u8]) -> Result<(), StdIoErr> {
        if self.is_reverse.get() {
            for &b in s.iter().rev() {
                let b = if self.is_little_endian.get() {
                    b.reverse_bits()
                } else {
                    b
                };
                write!(stream, "{:08b}", b)?;
            }
        } else {
            for &b in s.iter() {
                let b = if self.is_little_endian.get() {
                    b.reverse_bits()
                } else {
                    b
                };
                write!(stream, "{:08b}", b)?;
            }
        }

        Ok::<(), std::io::Error>(())
    }

    fn cvt_int(&self, stream: &mut Box<dyn Write>, s: &str) -> Result<(), StdIoErr> {
        let n = BigInt::from_str_radix(s, 10)
            .map_err(|e| StdIoErr::new(StdIoErrKind::Other, format!("{e}")))?;

        if self.is_little_endian.get() {
            let n = n.to_signed_bytes_le();
            let n = BigInt::from_signed_bytes_be(n.as_slice());
            write!(stream, "{:b}", n)
        } else {
            write!(stream, "{:b}", n)
        }
    }

    fn cvt_f32(&self, stream: &mut Box<dyn Write>, s: &str) -> Result<(), StdIoErr> {
        let s = s
            .parse::<f32>()
            .map_err(|e| StdIoErr::new(StdIoErrKind::Other, format!("{e}")))?
            .to_be_bytes();

        let s = if self.is_little_endian.get() {
            u32::from_le_bytes(s)
        } else {
            u32::from_be_bytes(s)
        };

        write!(stream, "{:032b}", s)
    }

    fn cvt_f64(&self, stream: &mut Box<dyn Write>, s: &str) -> Result<(), StdIoErr> {
        let s = s
            .parse::<f64>()
            .map_err(|e| StdIoErr::new(StdIoErrKind::Other, format!("{e}")))?
            .to_be_bytes();

        let s = if self.is_little_endian.get() {
            u64::from_le_bytes(s)
        } else {
            u64::from_be_bytes(s)
        };

        write!(stream, "{:064b}", s)
    }

    fn cvt(&self, stream: &mut Box<dyn Write>, s: &[u8]) -> Result<(), StdIoErr> {
        if self.is_0b.get() && !s.is_empty() {
            write!(stream, "0x")?;
        }

        match self.s_type.get() {
            SType::Str => self.cvt_str(stream, s),
            x => {
                let s = String::from_utf8(s.to_vec())
                    .map_err(|e| StdIoErr::new(StdIoErrKind::Other, e))?;
                if x == SType::F32 {
                    self.cvt_f32(stream, s.as_str())
                } else if x == SType::F64 {
                    self.cvt_f64(stream, s.as_str())
                } else {
                    self.cvt_int(stream, s.as_str())
                }
            }
        }
    }
}

impl Cmd for BinCmd {
    const NAME: &'static str = "bin";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("Convert a byte string convert to binary string")
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
            .arg(
                Arg::new("0b")
                    .long("0b")
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("Output hex string with prefix `0x`")
            )
            .arg(
                Arg::new("type")
                    .long("type")
                    .short('t')
                    .action(ArgAction::Set)
                    .default_value("str")
                    .value_parser(["str", "int", "f32", "f64"])
                    .help("to specify the byte string type")
            )
    }

    fn run(&self, m: &ArgMatches) {
        let (is_0b, is_little_endian, is_reverse) = (
            m.get_flag("0b"),
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

        let pro_err = |x: std::io::Result<()>| {
            if let Err(e) = x {
                if ErrorKind::BrokenPipe != e.kind() {
                    panic!("{e}")
                } else {
                    log::info!("{e}");
                }
            }
        };

        let s_type = m
            .get_one::<String>("type")
            .expect("need to specify the byte string type");

        self.is_0b(is_0b)
            .is_reverse(is_reverse)
            .is_little_endian(is_little_endian)
            .s_type(s_type.parse().unwrap());

        if !self.pipe_data.is_empty() {
            pro_err(self.cvt(&mut ostream, self.pipe_data.as_slice()));
        }

        if let Some(s) = p_str {
            pro_err(self.cvt(&mut ostream, s.as_bytes()));
        }

        if let Some(s) = input {
            let mut buf = vec![];
            let mut f = BufReader::new(File::open(s).unwrap());
            f.read_to_end(&mut buf).unwrap();
            pro_err(self.cvt(&mut ostream, buf.as_slice()));
        }

        pro_err(ostream.flush());
    }
}
