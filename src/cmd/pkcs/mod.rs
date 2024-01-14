use clap::Command;

use super::Cmd;

mod rsa;
pub use rsa::RSACmd;

#[derive(Clone)]
pub struct PKCSCmd;

impl Cmd for PKCSCmd {
    const NAME: &'static str = "p";
    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .subcommand_required(true)
            .subcommand(RSACmd::cmd())
            .about("Public key cryptography")
    }
    fn run(&self, m: &clap::ArgMatches) {
        match m.subcommand() {
            Some((RSACmd::NAME, m)) => RSACmd.run(m),
            Some((n, _m)) => panic!("unsupported subcommand {n}"),
            _ => unreachable!(),
        }
    }
}
