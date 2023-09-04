use std::time::SystemTime;

use chrono::{DateTime, Local};
use clap::Command;
use log::LevelFilter;
use my::cmd::{Cmd, GitCmd, MyFsCmd, TokeiCmd};

fn main() {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    let (myfs, tokei, git) = (MyFsCmd::new(), TokeiCmd::new(), GitCmd::new().unwrap());

    let version = format!("{}-{}", clap::crate_version!(), DateTime::<Local>::from(SystemTime::now()).format("%Y/%m/%d-%H:%M:%S:%Z"));
    let app = Command::new("my")
        .version(version)
        .about("my resource management")
        .subcommand(myfs.cmd())
        .subcommand(tokei.cmd())
        .subcommand(git.cmd())
        .get_matches();

    match app.subcommand() {
        Some((MyFsCmd::NAME, m)) => {
            myfs.run(m);
        }
        Some((TokeiCmd::NAME, m)) => {
            tokei.run(m);
        }
        Some((GitCmd::NAME, m)) => {
            git.run(m);
        }
        Some((name @ _, _)) => {
            panic!("unsupport for {}", name)
        }
        None => {}
    }
}
