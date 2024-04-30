use clap::{Arg, ArgAction, Command};
use log::LevelFilter;
use my::cmd::{
    Cmd, CryptoCmd, EncCmd, GitCmd, GroupCmd, HashCmd, KeyCmd, MACCmd, MyFsCmd, PKCSCmd, SignCmd,
    SkyCmd, TokeiCmd,
};
use std::io::Read;

fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    let version = concat!(env!("MY_VERSION_INFO"), " (", env!("MY_GIT_INFO"), ")");
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
        .subcommand(KeyCmd::cmd())
        .subcommand(SignCmd::cmd())
        .subcommand(MACCmd::cmd())
        .subcommand(CryptoCmd::cmd())
        .subcommand(PKCSCmd::cmd())
        .subcommand(GroupCmd::cmd())
        .get_matches();

    if let Some((s, m)) = app.subcommand() {
        let mut pdata = Vec::with_capacity(1024);
        if app.get_flag("pipe") {
            let _len = std::io::stdin().lock().read_to_end(&mut pdata).unwrap();
        }

        match s {
            MyFsCmd::NAME => MyFsCmd::new().run(m),
            TokeiCmd::NAME => TokeiCmd::new().run(m),
            GitCmd::NAME => GitCmd::new().unwrap().run(m),
            EncCmd::NAME => EncCmd::new(pdata.as_slice()).run(m),
            SkyCmd::NAME => SkyCmd {}.run(m),
            HashCmd::NAME => HashCmd::new(pdata.as_slice()).run(m),
            KeyCmd::NAME => KeyCmd.run(m),
            SignCmd::NAME => SignCmd.run(m),
            MACCmd::NAME => MACCmd.run(m),
            CryptoCmd::NAME => CryptoCmd.run(m),
            PKCSCmd::NAME => PKCSCmd.run(m),
            GroupCmd::NAME => GroupCmd.run(m),
            name => {
                panic!("unsupport for {}", name)
            }
        }
    } else {
        println!("{} {}", env!("CARGO_PKG_NAME"), version);
    }
}
