use super::{
    hash::{KMAC128Cmd, KMAC256Cmd, KMACXof128Cmd, KMACXof256Cmd},
    Cmd,
};
use clap::Command;

#[derive(Clone)]
pub struct MACCmd;

mod hmac;
pub use hmac::HMACCmd;

mod cmac;
pub use cmac::CMACCmd;

impl Cmd for MACCmd {
    const NAME: &'static str = "mac";
    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .subcommand_required(true)
            .subcommand(HMACCmd::cmd())
            .subcommand(KMAC128Cmd::cmd())
            .subcommand(KMAC256Cmd::cmd())
            .subcommand(KMACXof128Cmd::cmd())
            .subcommand(KMACXof256Cmd::cmd())
            .subcommand(CMACCmd::cmd())
            .about("Message Authentication Code")
    }

    fn run(&self, m: &clap::ArgMatches) {
        match m.subcommand() {
            Some((HMACCmd::NAME, m)) => HMACCmd.run(m),
            Some((KMAC128Cmd::NAME, m)) => KMAC128Cmd::new(&[]).run(m),
            Some((KMAC256Cmd::NAME, m)) => KMAC256Cmd::new(&[]).run(m),
            Some((KMACXof128Cmd::NAME, m)) => KMACXof128Cmd::new(&[]).run(m),
            Some((KMACXof256Cmd::NAME, m)) => KMACXof256Cmd::new(&[]).run(m),
            Some((CMACCmd::NAME, m)) => CMACCmd.run(m),
            Some((name, _m)) => panic!("not support the MAC of {name}"),
            None => unreachable!(),
        }
    }
}
