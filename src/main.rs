use clap::Parser;
use log::LevelFilter;
use my::cmd::{self, config::MyConfig, my_name, my_version, MySubCmd};
use std::io::Read;

fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    let cli = cmd::MyCli::parse();

    MyConfig::config_with_file(cli.config.as_deref());

    let pipe = cli.pipe.then(|| {
        let mut buf = MyConfig::tmp_buf();
        let _len = std::io::stdin().lock().read_to_end(&mut buf).unwrap();
        buf
    });

    if let Some(cmd) = cli.comand {
        match cmd {
            MySubCmd::Version => {
                println!("{} {}", my_name(), my_version());
            }
            MySubCmd::Hash(h) => h.exe(pipe.as_deref()),
            MySubCmd::Encode(e) => e.exe(pipe.as_deref()),
            MySubCmd::Git(g) => g.exe(pipe.as_deref()),
            MySubCmd::KDF(k) => k.exe(pipe.as_deref()),
            MySubCmd::MAC(m) => m.exe(pipe.as_deref()),
            MySubCmd::Crypto(c) => c.exe(pipe.as_deref()),
            MySubCmd::Sign(s) => s.exe(pipe.as_deref()),
            MySubCmd::Group(g) => g.exe(pipe.as_deref()),
            MySubCmd::Fs(f) => f.exe(pipe.as_deref()),
        }
    } else {
        println!("{} {}", my_name(), my_version());
    }
}
