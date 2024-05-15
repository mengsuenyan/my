use clap::Args;
use std::{collections::VecDeque, path::PathBuf, process::Command as StdCommand};

use crate::cmd::{config::MyConfig, guard::WorkingdirGuard};

use super::Git;

#[derive(Args)]
#[command(about = r#"update local git repository(using git fetch)
update all local git repositories using local git resources file if [DIRs] is empty and <LEVEL> is 0"#)]
pub struct UpdateArgs {
    #[arg(value_name = "DIRs", help = "directory that may be a git repository")]
    dirs: Vec<PathBuf>,

    #[arg(
        long,
        default_value = "1",
        help = "the max direcotry level to search git repository"
    )]
    level: usize,
}

impl UpdateArgs {
    pub fn exe(self, pipe: Vec<PathBuf>, git: Git) {
        let repo = Git::merge_path(self.dirs.as_slice(), pipe.as_slice());
        let mut git_res = if repo.is_empty() && self.level == 0 {
            log::info!("`my git update --level 0` will update all repos in the config file.");
            git.open_res_file()
        } else {
            git.search(repo.iter().copied(), self.level)
        };

        let mut infos = VecDeque::from(git_res.to_vec());
        let update_config_per_items = MyConfig::config().git.save_per_items;
        let cur_dir = match Git::cur_dir() {
            Ok(d) => d,
            Err(e) => {
                log::error!("cannot get current working direcotry: {}", e);
                return;
            }
        };

        git_res.clear();
        let mut cnt = 0;
        while let Some(rep) = infos.pop_back() {
            if git_res.git_info_nums() >= update_config_per_items {
                git.update_res_file(&git_res);
                git_res.clear();
            }
            cnt += 1;
            let path = rep.path().to_path_buf();
            let _guard = match WorkingdirGuard::new(&cur_dir, path.as_path()) {
                Ok(x) => x,
                Err(e) => {
                    log::error!("{e}");
                    continue;
                }
            };

            log::info!("{}", rep);
            match Git::git(StdCommand::new("git").args(["fetch", "origin"])) {
                Ok(s) => {
                    git_res.add_git_info(&rep);
                    log::info!("Ok. {} remaning `{}` repository to update", s, infos.len());
                    cnt = 0;
                }
                Err(e) => {
                    log::error!("{e}\nremaning `{} repository to update", infos.len() + 1);
                    if cnt < git.max_try() {
                        infos.push_front(rep)
                    } else {
                        log::warn!(
                            "{} update trying times exceed {}",
                            rep.path().display(),
                            git.max_try()
                        );
                        cnt = 0;
                    }
                }
            }

            if !infos.is_empty() {
                git.sleep();
            }
        }

        git.update_res_file(&git_res);
    }
}
