use crate::cmd::Cmd;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::PathBuf;

#[derive(Clone, Default)]
pub struct ByteCmd {
    pipe_data: String,
}

impl ByteCmd {
    pub fn new(pipe_data: String) -> Self {
        Self { pipe_data }
    }

    fn pro_bin(
        stream: &mut Box<dyn Write>,
        s: &[u8],
        is_reverse: bool,
        is_little_endian: bool,
    ) -> std::io::Result<()> {
        let cvt = |b| match b {
            b'0' => 0,
            b'1' => 1,
            _ => {
                panic!("{} is not valid binary character", char::from(b));
            }
        };

        if is_reverse {
            let mut num = 0;
            for (i, &b) in s.iter().rev().enumerate() {
                num |= b << (i & 7);
                if i & 7 == 7 {
                    stream.write_all(&[if is_little_endian {
                        num.reverse_bits()
                    } else {
                        num
                    }])?;
                    num = 0;
                }
            }

            if s.len() & 7 != 0 {
                stream.write_all(&[if is_little_endian {
                    num.reverse_bits()
                } else {
                    num
                }])?;
            }
        } else {
            for chunk in s.chunks(8) {
                let mut num = chunk.iter().fold(0u8, |a, &b| (a << 1) | cvt(b));
                if is_little_endian {
                    num = num.reverse_bits();
                }

                stream.write_all(&[num])?;
            }
        }

        Ok(())
    }

    fn pro_hex(
        stream: &mut Box<dyn Write>,
        s: &[u8],
        is_reverse: bool,
        is_little_endian: bool,
    ) -> std::io::Result<()> {
        let cvt = |b: &u8| match b {
            x if x.is_ascii_digit() => x - b'0',
            x if (b'a'..=b'f').contains(x) => 10 + (x - b'a'),
            x if (b'A'..=b'F').contains(x) => 10 + (x - b'A'),
            _ => {
                panic!("{} is not valid hex character", char::from(*b));
            }
        };

        if is_reverse {
            let mut num = 0;
            for (i, b) in s.iter().rev().enumerate() {
                if i & 1 == 1 {
                    num = if is_little_endian {
                        (num << 4) | cvt(b)
                    } else {
                        (cvt(b) << 4) | num
                    };

                    stream.write_all(&[num])?;
                } else {
                    num = cvt(b);
                }
            }

            if s.len() & 1 != 0 {
                if is_little_endian {
                    stream.write_all(&[num << 4])?;
                } else {
                    stream.write_all(&[num])?;
                }
            }
        } else {
            for b in s.chunks(2) {
                let mut num = b.iter().fold(0u8, |a, b| (a << 4) | cvt(b));

                if is_little_endian {
                    num = (num >> 4) | (num << 4)
                }
                stream.write_all(&[num])?;
            }
        }

        Ok(())
    }
}

impl Cmd for ByteCmd {
    const NAME: &'static str = "byte";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("Convert a string to byte string")
            .arg(
                Arg::new("str")
                    .value_name("STRING")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(String))
                    .required(false)
                    .help("some string")
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
                Arg::new("type")
                    .long("type")
                    .short('t')
                    .action(ArgAction::Set)
                    .default_value("str")
                    .value_parser(["str", "bin", "hex"])
            )
    }

    fn run(&self, m: &ArgMatches) {
        let (is_little_endian, is_reverse) = (m.get_flag("endian"), m.get_flag("reverse"));

        let (p_str, input, output) = (
            m.get_one::<String>("str"),
            m.get_one::<PathBuf>("filename"),
            m.get_one::<PathBuf>("output"),
        );

        let s_type = m.get_one::<String>("type").unwrap();

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
            if s_type == "str" {
                return stream.write_all(s);
            } else if s_type == "bin" {
                let s = if s.first().copied() == Some(b'0') && s.get(1).copied() == Some(b'b') {
                    &s[2..]
                } else {
                    s
                };

                Self::pro_bin(stream, s, is_reverse, is_little_endian)?;
            } else if s_type == "hex" {
                let s = if s.first().copied() == Some(b'0') && s.get(1).copied() == Some(b'x') {
                    &s[2..]
                } else {
                    s
                };
                Self::pro_hex(stream, s, is_reverse, is_little_endian)?;
            } else {
                panic!("invalid string type `{s_type}`");
            };

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
