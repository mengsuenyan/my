use crate::cmd::Cmd;
use clap::{ArgMatches, Command};

mod hex;
use hex::HexCmd;

mod bin;
use bin::BinCmd;

mod byte;
use byte::ByteCmd;

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
    }

    fn run(&self, m: &ArgMatches) {
        match m.subcommand() {
            Some((HexCmd::NAME, m)) => HexCmd::new(self.pipe_data.clone()).run(m),
            Some((BinCmd::NAME, m)) => BinCmd::new(self.pipe_data.clone()).run(m),
            Some((ByteCmd::NAME, m)) => ByteCmd::new(self.pipe_data.clone()).run(m),
            Some((name, _)) => {
                unimplemented!("Unsupport encode command `{}`", name)
            }
            None => {}
        }
    }
}
