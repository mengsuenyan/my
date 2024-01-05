use clap::{Arg, ArgAction, Command};
use log::LevelFilter;
use my::cmd::{Cmd, EncCmd, GitCmd, HashCmd, MyFsCmd, SkyCmd, TokeiCmd};
use std::io::Read;

fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    let version = env!("MY_VERSION_INFO");
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
        .subcommand(SkyCmd::cmd())
        .subcommand(HashCmd::cmd())
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
            EncCmd::NAME => EncCmd::new(pipe_data.as_str()).run(m),
            SkyCmd::NAME => SkyCmd {}.run(m),
            HashCmd::NAME => HashCmd::new(pipe_data.as_str()).run(m),
            name => {
                panic!("unsupport for {}", name)
            }
        }
    } else {
        println!("{} {}", env!("CARGO_PKG_NAME"), version);
    }
}
