use crate::cmd::Cmd;
use clap::{ArgMatches, Command};

mod rsa;
use rsa::RSACmd;

pub struct SignCmd;

impl Cmd for SignCmd {
    const NAME: &'static str = "s";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("signer")
            .subcommand(RSACmd::cmd())
            .subcommand_required(true)
    }

    fn run(&self, m: &ArgMatches) {
        match m.subcommand() {
            Some((RSACmd::NAME, m)) => RSACmd.run(m),
            Some((name, _m)) => panic!("not support the {name} cmd"),
            None => panic!("need to specify the sign subcommand"),
        }
    }
}
