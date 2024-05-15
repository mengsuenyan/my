use crate::cmd::git::Git;
use crate::fs::CodeInfo;
use crate::log_error;
use crate::ty::TableShow;
use clap::Args;
use std::path::PathBuf;
use std::process::Command as StdCommand;

#[derive(Args)]
#[command(about = "use tokei to count code")]
pub struct GitTokeiArgs {
    #[arg(value_name = "DIRs", help = "the git repository path")]
    dirs: Vec<PathBuf>,
}

impl GitTokeiArgs {
    fn tokei(cmd: &mut StdCommand) -> anyhow::Result<String> {
        let output = cmd.output().unwrap();

        if !output.status.success() {
            anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub fn exe(mut self, mut dirs: Vec<PathBuf>, git: Git) {
        self.dirs.append(&mut dirs);
        let mut res = git.open_res_file();
        for dir in self.dirs {
            let Some(dir) = log_error(dir.canonicalize().map_err(anyhow::Error::from)) else {
                continue;
            };

            let Some(tokei) = log_error(Self::tokei(
                StdCommand::new("tokei")
                    .arg("-C")
                    .args(["-s", "code"])
                    .args(["-o", "json"])
                    .arg(dir.as_os_str()),
            )) else {
                continue;
            };

            let Some(code_info) =
                log_error(CodeInfo::from_tokei_output(&tokei).map_err(anyhow::Error::from))
            else {
                continue;
            };

            println!("{}", code_info.table());

            res.update_code_info(dir.as_path(), code_info);
        }

        git.write_res_file(&res);
    }
}
