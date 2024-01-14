use std::{fmt::Write, fs::OpenOptions, io::Write as IOWrite, path::PathBuf};

use crate::cmd::Cmd;
use clap::{ArgMatches, Command};

mod rsa;
use rsa::RSACmd;

mod pbkdf;
pub use pbkdf::{PBKDF1Cmd, PBKDF2Cmd};

mod scrypt;
pub use scrypt::ScryptCmd;

mod argon;
pub use argon::Argon2Cmd;

mod plain;
pub use plain::PlainCmd;

fn write_to_file_or_stdout(m: &ArgMatches, data: &[u8]) -> anyhow::Result<()> {
    match m.get_one::<PathBuf>("output") {
        Some(p) => {
            let mut f = OpenOptions::new().create_new(true).write(true).open(p)?;
            f.write_all(data)?;
        }
        None => {
            let mut s = String::with_capacity(data.len() * 2);
            for x in data {
                s.write_fmt(format_args!("{:02x}", x))?;
            }
            println!("{}", s);
        }
    }
    Ok(())
}

#[derive(Default)]
pub struct KeyCmd;

impl Cmd for KeyCmd {
    const NAME: &'static str = "k";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("generate cipher key")
            .subcommand(RSACmd::cmd())
            .subcommand(PBKDF1Cmd::cmd())
            .subcommand(PBKDF2Cmd::cmd())
            .subcommand(ScryptCmd::cmd())
            .subcommand(Argon2Cmd::cmd())
            .subcommand(PlainCmd::cmd())
            .subcommand_required(true)
    }

    fn run(&self, m: &ArgMatches) {
        match m.subcommand() {
            Some((RSACmd::NAME, m)) => RSACmd.run(m),
            Some((PBKDF1Cmd::NAME, m)) => PBKDF1Cmd.run(m),
            Some((PBKDF2Cmd::NAME, m)) => PBKDF2Cmd.run(m),
            Some((ScryptCmd::NAME, m)) => ScryptCmd.run(m),
            Some((Argon2Cmd::NAME, m)) => Argon2Cmd.run(m),
            Some((PlainCmd::NAME, m)) => PlainCmd.run(m),
            Some((other, _m)) => panic!("not support the {other} key generation"),
            None => panic!("need to specify the key name"),
        }
    }
}
