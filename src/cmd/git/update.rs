use crate::{cmd::WorkingdirGuard, fs::GitRes};
use std::process::Command as StdCommand;
use std::{collections::VecDeque, path::PathBuf};

use super::GitCmd;

impl GitCmd {
    pub(super) fn update_cmd(&self, path: &[PathBuf], level: usize, max_try: usize) -> GitRes {
        let path = if path.is_empty() && level == 0 {
            log::info!("`my git --update 0` will update all repos in the config file.");
            let res = self.open_res_file();
            res.iter()
                .map(|x| x.path().to_path_buf())
                .collect::<Vec<_>>()
        } else {
            path.to_vec()
        };

        let mut git_res = self.res_cmd(&path, level);
        let mut infos = VecDeque::from(git_res.to_vec());
        let update_config_per_items = std::env::var("MY_GIT_UPDATE_ITEMS")
            .map(|x| x.parse::<usize>().unwrap_or(10))
            .unwrap_or(10);

        git_res.clear();
        let mut cnt = 0;
        while let Some(rep) = infos.pop_back() {
            if git_res.git_info_nums() >= update_config_per_items {
                self.update_res_file(&git_res);
                git_res.clear();
            }
            cnt += 1;
            let path = rep.path().to_path_buf();
            let _guard = WorkingdirGuard::new(&self.cur_dir, path.as_path());
            log::info!("{}", rep);
            match Self::git(StdCommand::new("git").args(["fetch", "origin"])) {
                Ok(s) => {
                    git_res.add_git_info(&rep);
                    log::info!("Ok. {} remaning `{}` repository to update", s, infos.len());
                    cnt = 0;
                }
                Err(e) => {
                    log::error!("{e}\nremaning `{} repository to update", infos.len() + 1);
                    if cnt < max_try {
                        infos.push_front(rep)
                    } else {
                        log::warn!(
                            "{} update trying times exceed {}",
                            rep.path().display(),
                            max_try
                        );
                        cnt = 0;
                    }
                }
            }

            if !infos.is_empty() {
                self.sleep();
            }
        }

        git_res
    }
}
