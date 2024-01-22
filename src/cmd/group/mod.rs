use clap::Command;

use super::Cmd;

mod fp;
pub use fp::FpCmd;

#[derive(Clone)]
pub struct GroupCmd;

impl Cmd for GroupCmd {
    const NAME: &'static str = "g";
    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .about("group")
            .subcommand_required(true)
            .subcommand(FpCmd::cmd())
    }
    fn run(&self, m: &clap::ArgMatches) {
        match m.subcommand() {
            Some((FpCmd::NAME, m)) => FpCmd.run(m),
            _ => unreachable!(),
        }
    }
}
