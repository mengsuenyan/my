use crate::cmd::Cmd;
use clap::{ArgMatches, Command};

mod rsa;
use rsa::RSACmd;

#[derive(Default)]
pub struct KeyCmd;

impl Cmd for KeyCmd {
    const NAME: &'static str = "k";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("generate cipher key")
            .subcommand(RSACmd::cmd())
    }

    fn run(&self, m: &ArgMatches) {
        match m.subcommand() {
            Some((RSACmd::NAME, m)) => RSACmd.run(m),
            Some((other, _m)) => panic!("not support the {other} key generation"),
            None => panic!("need to specify the key name"),
        }
    }
}
