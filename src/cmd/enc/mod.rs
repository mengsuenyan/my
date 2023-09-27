use crate::cmd::Cmd;
use clap::{ArgMatches, Command};

mod hex;
use hex::HexCmd;

mod bin;
use bin::BinCmd;

mod byte;
use byte::ByteCmd;

mod base;
use base::{Base16Cmd, Base32Cmd, Base58Cmd, Base64Cmd};

#[derive(Clone)]
pub struct EncCmd {
    pipe_data: String,
}

impl EncCmd {
    pub fn new(pipe_data: String) -> Self {
        Self { pipe_data }
    }
}

impl Cmd for EncCmd {
    const NAME: &'static str = "enc";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("Encode")
            .subcommand(HexCmd::cmd())
            .subcommand(BinCmd::cmd())
            .subcommand(ByteCmd::cmd())
            .subcommand(Base16Cmd::cmd())
            .subcommand(Base32Cmd::cmd())
            .subcommand(Base58Cmd::cmd())
            .subcommand(Base64Cmd::cmd())
    }

    fn run(&self, m: &ArgMatches) {
        match m.subcommand() {
            Some((HexCmd::NAME, m)) => HexCmd::new(self.pipe_data.clone()).run(m),
            Some((BinCmd::NAME, m)) => BinCmd::new(self.pipe_data.clone()).run(m),
            Some((ByteCmd::NAME, m)) => ByteCmd::new(self.pipe_data.clone()).run(m),
            Some((Base16Cmd::NAME, m)) => Base16Cmd::new(self.pipe_data.clone()).run(m),
            Some((Base32Cmd::NAME, m)) => Base32Cmd::new(self.pipe_data.clone()).run(m),
            Some((Base58Cmd::NAME, m)) => Base58Cmd::new(self.pipe_data.clone()).run(m),
            Some((Base64Cmd::NAME, m)) => Base64Cmd::new(self.pipe_data.clone()).run(m),
            Some((name, _)) => {
                unimplemented!("Unsupport encode command `{}`", name)
            }
            None => {}
        }
    }
}
