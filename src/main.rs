use chrono::{DateTime, Local};
use clap::{Arg, ArgAction, Command};
use log::LevelFilter;
use my::cmd::{Cmd, EncCmd, GitCmd, MyFsCmd, TokeiCmd};
use std::io::Read;
use std::time::SystemTime;

fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    let version = format!(
        "{}-{}",
        clap::crate_version!(),
        DateTime::<Local>::from(SystemTime::now()).format("%Y/%m/%d-%H:%M:%S:%Z")
    );
    let app = Command::new("my")
        .version(version)
        .about("my resource management")
        .arg(
            Arg::new("pipe")
                .long("pipe")
                .short('p')
                .action(ArgAction::SetTrue)
                .required(false),
        )
        .subcommand(MyFsCmd::cmd())
        .subcommand(TokeiCmd::cmd())
        .subcommand(GitCmd::cmd())
        .subcommand(EncCmd::cmd())
        .get_matches();

    if let Some((s, m)) = app.subcommand() {
        let mut pipe_data = String::new();
        if app.get_flag("pipe") {
            std::io::stdin().read_to_string(&mut pipe_data).unwrap();
        }

        match s {
            MyFsCmd::NAME => MyFsCmd::new().run(m),
            TokeiCmd::NAME => TokeiCmd::new().run(m),
            GitCmd::NAME => GitCmd::new().unwrap().run(m),
            EncCmd::NAME => EncCmd::new(pipe_data).run(m),
            name => {
                panic!("unsupport for {}", name)
            }
        }
    }
}
