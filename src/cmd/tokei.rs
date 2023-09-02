use std::{path::PathBuf, process::Command as StdCommand};

use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

use crate::{fs::CodeInfo, ty::TableShow, cmd::GitCmd};

use super::Cmd;

pub struct TokeiCmd;

impl TokeiCmd {
    pub fn new() -> Self {
        TokeiCmd
    }

    fn tokei(cmd: &mut StdCommand) -> String {
        let output = cmd.output().unwrap();

        if !output.status.success() {
            panic!("{}", String::from_utf8_lossy(&output.stderr));
        }

        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

impl Cmd for TokeiCmd {
    const NAME: &'static str = "tokei";

    fn cmd(&self) -> Command {
        Command::new(Self::NAME)
            .about("Use tokei to count code")
            .arg(
                Arg::new("dir")
                    .value_name("DIR")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("to specify the dir path"),
            )
    }

    fn run(&self, m: &ArgMatches) {
        let dir = match m.get_one::<PathBuf>("dir").cloned() {
            Some(dir) => dir.canonicalize().unwrap(),
            None => match std::env::current_dir() {
                Ok(dir) => dir,
                Err(e) => panic!("{}", e),
            },
        };

        let tokei = Self::tokei(
            StdCommand::new("tokei")
                .arg("-C")
                .args(["-s", "code"])
                .args(["-o", "json"])
                .arg(dir.to_string_lossy().as_ref()),
        );

        let code_info = CodeInfo::from_tokei_output(&tokei).unwrap();

        println!("{}", code_info.table());

        let git_cmd = match GitCmd::new() {
            Ok(cmd) => cmd,
            Err(e) => {
                log::error!("{e}");
                return;
            },
        };

        let mut res = git_cmd.open_res_file();
        res.update_code_info(dir.as_path(), code_info);
        git_cmd.write_res_file(&res);
    }
}
