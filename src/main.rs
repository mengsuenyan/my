use clap::Command;
use my::cmd::{Cmd, GitCmd, MyFsCmd, TokeiCmd};

fn main() {
    env_logger::init();

    let (myfs, tokei, git) = (MyFsCmd::new(), TokeiCmd::new(), GitCmd::new().unwrap());

    let app = Command::new("my")
        .version("0.1.0")
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
