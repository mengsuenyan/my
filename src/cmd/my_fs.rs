use std::path::{Path, PathBuf};

use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

use crate::fs::ResourceInfo;
use crate::ty::TableShow;

use super::Cmd;

pub struct MyFsCmd;

impl MyFsCmd {
    pub fn new() -> Self {
        MyFsCmd
    }
}

impl Cmd for MyFsCmd {
    const NAME: &'static str = "fs";

    fn cmd(&self) -> Command {
        Command::new(Self::NAME)
            .about("my filesystem management")
            .arg(
                Arg::new("dir")
                    .value_name("DIR")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(String))
                    .required(true)
                    .help("to specify the dir path"),
            )
            .arg(
                Arg::new("list")
                    .long("list")
                    .short('l')
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .help("list the specified directory"),
            )
            .arg(
                Arg::new("tree")
                    .long("tree")
                    .short('t')
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .conflicts_with("list")
                    .help("tree the specified directory"),
            )
            .arg(
                Arg::new("level")
                    .long("lvl")
                    .required(false)
                    .action(ArgAction::Set)
                    .default_value("1")
                    .value_parser(clap::value_parser!(usize))
                    .conflicts_with("list")
                    .help("specified the level for the tree"),
            )
            .arg(
                Arg::new("table")
                    .long("table")
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .help("show the result as table"),
            )
            .arg(
                Arg::new("type")
                    .long("type")
                    .required(false)
                    .action(ArgAction::Set)
                    .value_parser(clap::value_parser!(String))
                    .help("specified the resource type: dir | file | symlink"),
            )
    }

    fn run(&self, m: &ArgMatches) {
        let dir = m.get_one::<String>("dir").expect("dir path").clone();

        let res_info = match ResourceInfo::new(PathBuf::from(dir)) {
            Ok(myfs) => myfs,
            Err(e) => panic!("{}", e),
        };

        let filter: Box<dyn Fn(&Path) -> bool> =
            match m.get_one::<String>("type").map(|s| s.as_str()) {
                Some("file") => Box::new(|p| p.is_file()),
                Some("dir") => Box::new(|p| p.is_dir()),
                Some("symlink") => Box::new(|p| p.is_symlink()),
                Some(_) => Box::new(|_| false),
                None => Box::new(|_| true),
            };

        let res = if m.get_flag("list") {
            res_info.list()
        } else if m.get_flag("tree") {
            let level = m.get_one::<usize>("level").expect("tree level").clone();

            res_info.tree_with_cond(level, filter, |_| true)
        } else {
            unreachable!()
        };

        if m.get_flag("table") {
            println!("{}", res.table());
        } else {
            println!("{}", res);
        }
    }
}
