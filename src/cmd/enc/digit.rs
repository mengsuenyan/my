use std::io::{Read, Write};

use clap::{builder::PossibleValuesParser, Args};
use num_bigint::BigUint;
use num_traits::Num;

use crate::cmd::config::MyConfig;

use super::base::BaseArgs;

#[derive(Args)]
struct DigitArgs {
    #[command(flatten)]
    base: BaseArgs,

    #[arg(long)]
    #[arg(help = r#"interpret the input data with litte-endian
this only work with type [int, f32, f64]"#)]
    le: bool,

    #[arg(short, long, default_value = "str", value_parser = PossibleValuesParser::new(["str", "int", "f32", "f64"]))]
    r#type: String,
}

#[derive(Args)]
#[command(about = "hex(PIPE | STRING | file)")]
pub struct HexArgs {
    #[command(flatten)]
    common: DigitArgs,

    #[arg(long = "0x")]
    #[arg(help = "input/output with prefix 0x when encode data")]
    prefix: bool,
}

#[derive(Args)]
#[command(about = "bin(PIPE | STRING | file)")]
pub struct BinArgs {
    #[command(flatten)]
    common: DigitArgs,

    #[arg(long = "0b")]
    #[arg(help = "input/output with prefix 0b when encode data")]
    prefix: bool,
}

impl HexArgs {
    pub fn exe(self, pipe: Option<&[u8]>) {
        let file_data = self.common.base.io.read_all_data().unwrap();
        let mut ostream = self
            .common
            .base
            .io
            .writer_with_default(MyConfig::config().io_buf_size)
            .unwrap();

        if let Some(data) = pipe {
            self.cvt(data, &mut ostream);
        }

        if let Some(data) = self.common.base.str.as_deref() {
            self.cvt(data.as_bytes(), &mut ostream);
        }

        if let Some(data) = file_data.as_deref() {
            self.cvt(data, &mut ostream)
        }
    }

    fn cvt<R: Read, W: Write>(&self, istream: R, ostream: &mut W) {
        if self.common.r#type == "str" {
            self.cvt_str(istream, ostream);
        } else if self.common.r#type == "int" {
            self.cvt_int(istream, ostream);
        } else if self.common.r#type == "f32" {
            self.cvt_f(istream, ostream, 4);
        } else if self.common.r#type == "f64" {
            self.cvt_f(istream, ostream, 8);
        } else {
            unreachable!("not support type")
        }
    }

    fn cvt_f<R: Read, W: Write>(&self, mut istream: R, ostream: &mut W, flen: usize) {
        let mut buf = String::with_capacity(64);
        istream.read_to_string(&mut buf).unwrap();

        if self.common.base.decode {
            let buf = buf.as_bytes();
            let d = if buf.len() > 1 && buf[0] == b'0' && (buf[1] == b'x' || buf[1] == b'X') {
                &buf[2..]
            } else {
                buf
            };

            assert!(
                d.len() < flen * 2 + 1,
                "invlaid float hex string length `{}`",
                flen
            );
            let (mut a, mut b) = (vec![0u8; flen], vec![0u8; flen * 2]);
            d.iter().rev().zip(b.iter_mut().rev()).for_each(|(x, y)| {
                *y = if x.is_ascii_digit() {
                    x - b'0'
                } else if (b'a'..=b'f').contains(x) {
                    x - b'a' + 10
                } else if (b'A'..=b'F').contains(x) {
                    x - b'A' + 10
                } else {
                    panic!(
                        "invalid {} hex data {}",
                        if flen == 4 { "f32" } else { "f64" },
                        x
                    );
                }
            });

            a.iter_mut().enumerate().for_each(|(i, x)| {
                *x = (b[i * 2] << 4) | b[i * 2 + 1];
            });

            if flen == 4 {
                ostream
                    .write_fmt(format_args!(
                        "{}",
                        f32::from_be_bytes(a.as_slice().try_into().unwrap())
                    ))
                    .unwrap();
            } else if flen == 8 {
                ostream
                    .write_fmt(format_args!(
                        "{}",
                        f64::from_be_bytes(a.as_slice().try_into().unwrap())
                    ))
                    .unwrap();
            }
        } else {
            if self.prefix {
                let _ = ostream.write("0x".as_bytes()).unwrap();
            }

            if flen == 4 {
                let d = buf.parse::<f32>().unwrap();
                ostream
                    .write_fmt(format_args!("{:x}", d.to_bits()))
                    .unwrap();
            } else if flen == 8 {
                let d = buf.parse::<f64>().unwrap();
                ostream
                    .write_fmt(format_args!("{:x}", d.to_bits()))
                    .unwrap();
            }
        }
    }

    fn cvt_int<R: Read, W: Write>(&self, mut istream: R, ostream: &mut W) {
        let mut buf = MyConfig::tmp_buf();
        istream.read_to_end(&mut buf).unwrap();

        if self.common.base.decode {
            let d = if buf.len() > 1 && buf[0] == b'0' && (buf[1] == b'x' || buf[1] == b'X') {
                &buf[2..]
            } else {
                buf.as_slice()
            };

            let d = std::str::from_utf8(d).unwrap();
            let d = BigUint::from_str_radix(d, 16).unwrap();
            ostream.write_fmt(format_args!("{}", d)).unwrap();
        } else {
            let d = std::str::from_utf8(&buf).unwrap();
            let d = BigUint::from_str_radix(d, 10).unwrap();
            if self.prefix {
                let _ = ostream.write("0x".as_bytes()).unwrap();
            }

            ostream.write_fmt(format_args!("{:x}", d)).unwrap();
        }
    }

    fn cvt_str<R: Read, W: Write>(&self, mut istream: R, ostream: &mut W) {
        if self.common.base.decode {
            const TABLE: [u8; 256] = [
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 0,
                1, 2, 3, 4, 5, 6, 7, 8, 9, 127, 127, 127, 127, 127, 127, 127, 10, 11, 12, 13, 14,
                15, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 10, 11, 12, 13, 14, 15, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127,
            ];

            if self.prefix {
                let mut d = [0u8, 0u8];
                let _ = istream.read(&mut d).unwrap();
                assert!(&d == b"0x" || &d == b"0X", "the prefix {:?} is not 0x", d);
            }

            let (mut tmp, mut d) = (MyConfig::tmp_buf(), [0u8, 0u8]);
            loop {
                let n = istream.read(&mut d).unwrap();
                let (a, b) = (TABLE[d[0] as usize], TABLE[d[1] as usize]);
                if n == 2 {
                    assert!(
                        a != 127 && b != 127,
                        "{} or {} not hex data character",
                        d[0],
                        d[1]
                    );
                    tmp.push((a << 4) | b);
                } else if n == 1 {
                    assert!(a != 127, "{} not hex data character", d[0],);
                    tmp.push(a);
                } else if n == 0 {
                    break;
                }
            }

            ostream
                .write_all(String::from_utf8(tmp).unwrap().as_bytes())
                .unwrap();
        } else {
            if self.prefix {
                let _ = ostream.write("0x".as_bytes()).unwrap();
            }

            for b in istream.bytes() {
                ostream
                    .write_fmt(format_args!("{:02x}", b.unwrap()))
                    .unwrap();
            }
        }
    }
}

impl BinArgs {
    pub fn exe(self, pipe: Option<&[u8]>) {
        let file_data = self.common.base.io.read_all_data().unwrap();
        let mut ostream = self
            .common
            .base
            .io
            .writer_with_default(MyConfig::config().io_buf_size)
            .unwrap();

        if let Some(data) = pipe {
            self.cvt(data, &mut ostream);
        }

        if let Some(data) = self.common.base.str.as_deref() {
            self.cvt(data.as_bytes(), &mut ostream);
        }

        if let Some(data) = file_data.as_deref() {
            self.cvt(data, &mut ostream)
        }
    }

    fn cvt<R: Read, W: Write>(&self, istream: R, ostream: &mut W) {
        if self.common.r#type == "str" {
            self.cvt_str(istream, ostream);
        } else if self.common.r#type == "int" {
            self.cvt_int(istream, ostream);
        } else if self.common.r#type == "f32" {
            self.cvt_f(istream, ostream, 4);
        } else if self.common.r#type == "f64" {
            self.cvt_f(istream, ostream, 8);
        } else {
            unreachable!("not support type")
        }
    }

    fn cvt_f<R: Read, W: Write>(&self, mut istream: R, ostream: &mut W, flen: usize) {
        let mut buf = String::with_capacity(64);
        istream.read_to_string(&mut buf).unwrap();

        if self.common.base.decode {
            let buf = buf.as_bytes();
            let d = if buf.len() > 1 && buf[0] == b'0' && (buf[1] == b'b' || buf[1] == b'B') {
                &buf[2..]
            } else {
                buf
            };

            assert!(
                d.len() < flen * 8 + 1,
                "invlaid float hex string length `{}`",
                flen
            );
            let (mut a, mut b) = (vec![0u8; flen], vec![0u8; flen * 8]);
            d.iter().rev().zip(b.iter_mut().rev()).for_each(|(&x, y)| {
                *y = if x == b'0' || x == b'1' {
                    x - b'0'
                } else {
                    panic!(
                        "invalid {} binary data {}",
                        if flen == 4 { "f32" } else { "f64" },
                        x
                    );
                };
            });

            a.iter_mut().enumerate().for_each(|(i, x)| {
                *x = b[i * 8] << 7
                    | b[i * 8 + 1] << 6
                    | b[i * 8 + 2] << 5
                    | b[i * 8 + 3] << 4
                    | b[i * 8 + 4] << 3
                    | b[i * 8 + 5] << 2
                    | b[i * 8 + 6] << 1
                    | b[i * 8 + 7];
            });

            if flen == 4 {
                ostream
                    .write_fmt(format_args!(
                        "{}",
                        f32::from_be_bytes(a.as_slice().try_into().unwrap())
                    ))
                    .unwrap();
            } else if flen == 8 {
                ostream
                    .write_fmt(format_args!(
                        "{}",
                        f64::from_be_bytes(a.as_slice().try_into().unwrap())
                    ))
                    .unwrap();
            }
        } else {
            if self.prefix {
                let _ = ostream.write("0b".as_bytes()).unwrap();
            }

            if flen == 4 {
                let d = buf.parse::<f32>().unwrap();
                ostream
                    .write_fmt(format_args!("{:b}", d.to_bits()))
                    .unwrap();
            } else if flen == 8 {
                let d = buf.parse::<f64>().unwrap();
                ostream
                    .write_fmt(format_args!("{:b}", d.to_bits()))
                    .unwrap();
            }
        }
    }

    fn cvt_int<R: Read, W: Write>(&self, mut istream: R, ostream: &mut W) {
        let mut buf = MyConfig::tmp_buf();
        istream.read_to_end(&mut buf).unwrap();

        if self.common.base.decode {
            let d = if buf.len() > 1 && buf[0] == b'0' && (buf[1] == b'b' || buf[1] == b'B') {
                &buf[2..]
            } else {
                buf.as_slice()
            };

            let d = std::str::from_utf8(d).unwrap();
            let d = BigUint::from_str_radix(d, 2).unwrap();
            ostream.write_fmt(format_args!("{}", d)).unwrap();
        } else {
            let d = std::str::from_utf8(&buf).unwrap();
            let d = BigUint::from_str_radix(d, 10).unwrap();
            if self.prefix {
                let _ = ostream.write("0b".as_bytes()).unwrap();
            }

            ostream.write_fmt(format_args!("{:b}", d)).unwrap();
        }
    }

    fn cvt_str<R: Read, W: Write>(&self, mut istream: R, ostream: &mut W) {
        if self.common.base.decode {
            if self.prefix {
                let mut d = [0u8, 0u8];
                let _ = istream.read(&mut d).unwrap();
                assert!(&d == b"0b" || &d == b"0B", "the prefix {:?} is not 0b", d);
            }

            let (mut tmp, mut d) = (MyConfig::tmp_buf(), [0u8; 8]);
            loop {
                let n = istream.read(&mut d).unwrap();
                if n == 0 {
                    break;
                } else {
                    tmp.push(d.iter().take(n).fold(0, |x, &y| {
                        assert!(y == b'0' || y == b'1', "{} not binary data character", y);
                        (x << 1) | (y - b'0')
                    }));
                }
            }

            ostream
                .write_all(String::from_utf8(tmp).unwrap().as_bytes())
                .unwrap();
        } else {
            if self.prefix {
                let _ = ostream.write("0b".as_bytes()).unwrap();
            }

            let mut tmp = [0u8; 8];
            for b in istream.bytes() {
                let mut b = b.unwrap();
                tmp.iter_mut().rev().for_each(|x| {
                    *x = (b & 1) + b'0';
                    b >>= 1;
                });
                ostream.write_all(&tmp).unwrap();
            }
        }
    }
}
