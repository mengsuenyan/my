use super::Cmd;
use anyhow::Result;
use cipher::Cipher;
use clap::{ArgMatches, Command};
use std::{
    fs::{read, write},
    path::PathBuf,
    thread::scope,
};

pub mod block;
pub use block::{AES128Cmd, AES192Cmd, AES256Cmd, SM4Cmd};

pub mod mode;
pub use mode::{CBCCmd, CBCsCmd, CFBCmd, CTRCmd, ECBCmd, OFBCmd};

mod stream;
pub use stream::ZUCCmd;

mod ae;
pub use ae::{CCMCmd, GCMCmd};

fn common_crypto(mut c: Vec<Box<dyn Cipher + Send + Sync>>, m: &ArgMatches) -> Result<()> {
    let ipaths = m
        .get_many::<PathBuf>("file")
        .map(|x| x.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let opaths = m
        .get_many::<PathBuf>("output")
        .map(|x| x.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let msg = m.get_one::<String>("msg");
    let is_decrypt = m.get_flag("decrypt");

    anyhow::ensure!(
        ipaths.len() == opaths.len(),
        "the file path numbers must equal to output path numbers"
    );
    if let Some(msg) = msg {
        if let Some(c) = c.pop() {
            let mut buf = Vec::with_capacity(128);
            if is_decrypt {
                c.decrypt(msg.as_bytes(), &mut buf)?;
            } else {
                c.encrypt(msg.as_bytes(), &mut buf)?;
            }
            for x in buf {
                print!("{:02x}", x);
            }
            println!();
        }
    }

    if c.len() < 2 {
        for (c, (ipath, opath)) in c.into_iter().zip(ipaths.into_iter().zip(opaths)) {
            let (data, mut buf) = (read(ipath)?, Vec::with_capacity(1024));
            if is_decrypt {
                c.decrypt(&data, &mut buf)?;
            } else {
                c.encrypt(&data, &mut buf)?;
            }
            write(opath, buf)?;
        }
        Ok(())
    } else {
        scope::<'_, _, Result<()>>(move |s| {
            for (c, (ipath, opath)) in c.into_iter().zip(ipaths.into_iter().zip(opaths)) {
                s.spawn::<_, Result<()>>(move || {
                    let (data, mut buf) = (read(ipath)?, Vec::with_capacity(1024));
                    if is_decrypt {
                        c.decrypt(&data, &mut buf)?;
                    } else {
                        c.encrypt(&data, &mut buf)?;
                    }
                    write(opath, buf)?;
                    Ok(())
                });
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct CryptoCmd;

impl Cmd for CryptoCmd {
    const NAME: &'static str = "c";
    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .about("crypto")
            .subcommand_required(true)
            .subcommand(SM4Cmd::cmd())
            .subcommand(AES128Cmd::cmd())
            .subcommand(AES192Cmd::cmd())
            .subcommand(AES256Cmd::cmd())
            .subcommand(ECBCmd::cmd())
            .subcommand(CBCCmd::cmd())
            .subcommand(CFBCmd::cmd())
            .subcommand(OFBCmd::cmd())
            .subcommand(CTRCmd::cmd())
            .subcommand(CBCsCmd::cmd())
            .subcommand(ZUCCmd::cmd())
            .subcommand(CCMCmd::cmd())
            .subcommand(GCMCmd::cmd())
    }
    fn run(&self, m: &clap::ArgMatches) {
        let Some((name, sm)) = m.subcommand() else {
            panic!("need to specify the subcommond for the crypto cmd");
        };

        match name {
            SM4Cmd::NAME => SM4Cmd.run(sm),
            AES128Cmd::NAME => AES128Cmd.run(sm),
            AES192Cmd::NAME => AES192Cmd.run(sm),
            AES256Cmd::NAME => AES256Cmd.run(sm),
            ECBCmd::NAME => ECBCmd.run(sm),
            CBCCmd::NAME => CBCCmd.run(sm),
            CFBCmd::NAME => CFBCmd.run(sm),
            OFBCmd::NAME => OFBCmd.run(sm),
            CTRCmd::NAME => CTRCmd.run(sm),
            CBCsCmd::NAME => CBCsCmd.run(sm),
            ZUCCmd::NAME => ZUCCmd.run(sm),
            CCMCmd::NAME => CCMCmd.run(sm),
            GCMCmd::NAME => GCMCmd.run(sm),
            x => panic!("not support the subcommond {x}"),
        }
    }
}
