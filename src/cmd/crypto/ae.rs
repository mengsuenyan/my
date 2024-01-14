use super::mode;
use crate::cmd::Cmd;
use anyhow::Result;
use cipher::ae::{AuthenticationCipherX, CCM, GCM};
use clap::{value_parser, Arg, ArgAction};
use std::fs::read;
use std::{path::PathBuf, thread::scope};

#[derive(Clone)]
pub struct CCMCmd;
#[derive(Clone)]
pub struct GCMCmd;

impl Cmd for CCMCmd {
    const NAME: &'static str = "ccm";
    fn cmd() -> clap::Command {
        mode::common_command(Self::NAME)
            .about("Counter with Cipher Block Chaining-Message Authentication Code")
            .arg(
                Arg::new("mac")
                    .help("mac size")
                    .long("mac")
                    .default_value("16")
                    .action(ArgAction::Set)
                    .value_parser(["4", "6", "8", "10", "12", "14", "16"])
                    .required(false),
            )
            .arg(
                Arg::new("nonce")
                    .help("nonce size need in the [7,13]")
                    .long("nonce")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true),
            )
            .arg(
                Arg::new("ad")
                    .help("associated data")
                    .long("ad")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true),
            )
    }

    fn run(&self, m: &clap::ArgMatches) {
        let (bc, bm) = mode::common_run(Self::NAME, m).unwrap();
        let (mac, nonce, ad, ipaths, opaths, msg, is_decrypt) = (
            m.get_one::<String>("mac")
                .map(|x| x.parse::<usize>().unwrap())
                .unwrap(),
            m.get_one::<PathBuf>("nonce").unwrap(),
            m.get_one::<PathBuf>("ad").unwrap(),
            bm.get_many::<PathBuf>("file")
                .map(|x| x.cloned().collect::<Vec<_>>())
                .unwrap_or_default(),
            bm.get_many::<PathBuf>("output")
                .map(|x| x.cloned().collect::<Vec<_>>())
                .unwrap_or_default(),
            bm.get_one::<String>("msg").cloned().unwrap_or_default(),
            bm.get_flag("decrypt"),
        );

        assert_eq!(
            ipaths.len(),
            opaths.len(),
            "the file path numbers must equal to output path numbers"
        );

        let mut ccm = Vec::with_capacity(bc.len());
        for x in bc {
            ccm.push(CCM::new(x, mac).unwrap())
        }

        let (nonce, ad) = (read(nonce).unwrap(), read(ad).unwrap());
        let (nonce, ad) = (nonce.as_slice(), ad.as_slice());
        if !msg.is_empty() {
            let ccm = ccm.pop().unwrap();
            let (msg, mut buf) = (msg.as_bytes(), Vec::with_capacity(msg.len() + 128));
            if is_decrypt {
                ccm.auth_decrypt_x(nonce, ad, msg, &mut buf).unwrap();
            } else {
                ccm.auth_encrypt_x(nonce, ad, msg, &mut buf).unwrap();
            }
            for x in buf {
                print!("{:02x}", x);
            }
            println!()
        }

        if ccm.len() < 2 {
            for (c, (ipath, opath)) in ccm.into_iter().zip(ipaths.into_iter().zip(opaths)) {
                let data = std::fs::read(ipath).unwrap();
                let (data, mut buf) = (data.as_slice(), Vec::with_capacity(data.len() + 128));
                if is_decrypt {
                    c.auth_decrypt_x(nonce, ad, data, &mut buf).unwrap();
                } else {
                    c.auth_encrypt_x(nonce, ad, data, &mut buf).unwrap();
                }
                std::fs::write(opath, data).unwrap();
            }
        } else {
            let x = scope::<'_, _, Result<()>>(move |s| {
                for (c, (ipath, opath)) in ccm.into_iter().zip(ipaths.into_iter().zip(opaths)) {
                    s.spawn::<_, Result<()>>(move || {
                        let data = std::fs::read(ipath)?;
                        let (data, mut buf) =
                            (data.as_slice(), Vec::with_capacity(data.len() + 128));
                        if is_decrypt {
                            c.auth_decrypt_x(nonce, ad, data, &mut buf)?;
                        } else {
                            c.auth_encrypt_x(nonce, ad, data, &mut buf)?;
                        }
                        std::fs::write(opath, data)?;
                        Ok(())
                    });
                }
                Ok(())
            });

            x.unwrap();
        }
    }
}

impl Cmd for GCMCmd {
    const NAME: &'static str = "gcm";
    fn cmd() -> clap::Command {
        mode::common_command(Self::NAME)
            .about("Galois/Counter Mode(GCM) and GMAC")
            .arg(
                Arg::new("mac")
                    .help("mac size")
                    .long("mac")
                    .default_value("16")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(u64).range(0..=16))
                    .required(false),
            )
            .arg(
                Arg::new("nonce")
                    .help("nonce need not empty")
                    .long("nonce")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true),
            )
            .arg(
                Arg::new("ad")
                    .help("associated data")
                    .long("ad")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true),
            )
    }

    fn run(&self, m: &clap::ArgMatches) {
        let (bc, bm) = mode::common_run(Self::NAME, m).unwrap();
        let (mac, nonce, ad, ipaths, opaths, msg, is_decrypt) = (
            m.get_one::<String>("mac")
                .map(|x| x.parse::<usize>().unwrap())
                .unwrap(),
            m.get_one::<PathBuf>("nonce").unwrap(),
            m.get_one::<PathBuf>("ad").unwrap(),
            bm.get_many::<PathBuf>("file").unwrap().collect::<Vec<_>>(),
            bm.get_many::<PathBuf>("output")
                .unwrap()
                .collect::<Vec<_>>(),
            bm.get_one::<String>("msg").cloned().unwrap_or_default(),
            bm.get_flag("decrypt"),
        );

        assert_eq!(
            ipaths.len(),
            opaths.len(),
            "the file path numbers must equal to output path numbers"
        );

        let mut ccm = Vec::with_capacity(bc.len());
        for x in bc {
            ccm.push(GCM::new(x, mac).unwrap())
        }

        let (nonce, ad) = (read(nonce).unwrap(), read(ad).unwrap());
        let (nonce, ad) = (nonce.as_slice(), ad.as_slice());
        if !msg.is_empty() {
            let ccm = ccm.pop().unwrap();
            let (msg, mut buf) = (msg.as_bytes(), Vec::with_capacity(msg.len() + 128));
            if is_decrypt {
                ccm.auth_decrypt_x(nonce, ad, msg, &mut buf).unwrap();
            } else {
                ccm.auth_encrypt_x(nonce, ad, msg, &mut buf).unwrap();
            }
            for x in buf {
                print!("{:02x}", x);
            }
            println!()
        }

        if ccm.len() < 2 {
            for (c, (ipath, opath)) in ccm.into_iter().zip(ipaths.into_iter().zip(opaths)) {
                let data = std::fs::read(ipath).unwrap();
                let (data, mut buf) = (data.as_slice(), Vec::with_capacity(data.len() + 128));
                if is_decrypt {
                    c.auth_decrypt_x(nonce, ad, data, &mut buf).unwrap();
                } else {
                    c.auth_encrypt_x(nonce, ad, data, &mut buf).unwrap();
                }
                std::fs::write(opath, data).unwrap();
            }
        } else {
            let x = scope::<'_, _, Result<()>>(move |s| {
                for (c, (ipath, opath)) in ccm.into_iter().zip(ipaths.into_iter().zip(opaths)) {
                    s.spawn::<_, Result<()>>(move || {
                        let data = std::fs::read(ipath)?;
                        let (data, mut buf) =
                            (data.as_slice(), Vec::with_capacity(data.len() + 128));
                        if is_decrypt {
                            c.auth_decrypt_x(nonce, ad, data, &mut buf)?;
                        } else {
                            c.auth_encrypt_x(nonce, ad, data, &mut buf)?;
                        }
                        std::fs::write(opath, data)?;
                        Ok(())
                    });
                }
                Ok(())
            });

            x.unwrap();
        }
    }
}
