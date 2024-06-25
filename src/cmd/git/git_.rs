use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    process::Command as StdCommand,
    time::Duration,
};

use regex::Regex;

use crate::{
    cmd::{config::MyConfig, guard::WorkingdirGuard},
    error::MyError,
    fs::{GitInfo, GitRes, ResourceInfo},
};

use super::CommonArgs;

#[derive(Clone, PartialEq, Eq)]
pub struct Git {
    common: CommonArgs,
}

impl Git {
    pub fn max_try(&self) -> usize {
        self.common.max_try
    }

    pub fn cur_dir() -> anyhow::Result<PathBuf> {
        Ok(std::env::current_dir()?)
    }

    fn config_path(&self) -> &Path {
        &MyConfig::config().git.meta_info
    }

    fn config_backup_path(&self) -> &Path {
        &MyConfig::config().git.meta_info_backup
    }

    pub(super) fn sleep(&self) {
        let s = rand::random::<u64>() % self.common.sleep;
        std::thread::sleep(Duration::from_secs(s));
    }

    pub(super) fn git(cmd: &mut StdCommand) -> anyhow::Result<String> {
        let output = cmd.output().unwrap();

        if !output.status.success() {
            anyhow::bail!(MyError::GitFailed(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        } else {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    }

    /// 合并两个路径集, 集合中的每个元素表示目录路径且目录是存在的
    pub fn merge_path<'a>(aset: &'a [PathBuf], bset: &'a [PathBuf]) -> HashSet<&'a Path> {
        bset.iter()
            .chain(aset)
            .filter(|p| {
                if p.is_dir() {
                    true
                } else {
                    log::error!("{} is not directory", p.display());
                    false
                }
            })
            .map(|x| x.as_path())
            .collect::<HashSet<_>>()
    }

    pub fn open_res_file(&self) -> GitRes {
        if self.config_path().is_file() {
            let content = std::fs::read_to_string(self.config_path()).unwrap();
            serde_json::from_str::<GitRes>(&content).unwrap()
        } else {
            GitRes::new()
        }
    }

    pub fn update_res_file(&self, git_res: &GitRes) {
        if git_res.git_info_nums() > 0 {
            let mut res = self.open_res_file();
            res.merge(git_res);
            self.write_res_file(&res);
        }
    }

    pub fn write_res_file(&self, git_res: &GitRes) {
        let new_content = serde_json::to_string_pretty(&git_res).unwrap();

        match std::fs::write(self.config_path(), new_content.as_bytes()) {
            Ok(_) => {
                std::fs::copy(self.config_path(), self.config_backup_path()).unwrap();
            }
            Err(e) => {
                std::fs::copy(self.config_backup_path(), self.config_path()).unwrap();
                panic!("{e}");
            }
        }
    }

    /// git remote -v
    pub fn remote(&self, path: &Path, is_only_url: bool) -> anyhow::Result<GitInfo> {
        let path = path.canonicalize()?;
        let path = path.as_path();
        let cur_dir = Self::cur_dir()?;
        let _guard = WorkingdirGuard::new(cur_dir.as_path(), path)?;
        let s = Self::git(StdCommand::new("git").args(["remote", "-v"]))?;
        let git_info = GitInfo::new(path);

        let re = Regex::new(r"\w+\s+(?<url>.*)\s+\(")
            .map_err(|e| MyError::RegexFailed(format!("{e}")))?;
        for line in s.lines() {
            if let Some(cap) = re.captures(line) {
                if let Some(s) = cap.name("url") {
                    if !is_only_url {
                        match path.metadata() {
                            Ok(m) => match m.modified() {
                                Ok(m) => {
                                    return Ok(git_info.set_url(s.as_str()).set_modified(m));
                                }
                                Err(e) => {
                                    log::error!(
                                        "get modified time of `{}` failed, due to {}",
                                        path.display(),
                                        e
                                    );
                                }
                            },
                            Err(e) => {
                                log::error!(
                                    "get metadata of `{}` failed, due to {}",
                                    path.display(),
                                    e
                                );
                            }
                        }
                    }

                    return Ok(git_info.set_url(s.as_str()));
                }
            }
        }

        anyhow::bail!(MyError::GitNotFoundAddr(format!(
            "addr {s} not found in the `{}`",
            path.display()
        )));
    }

    /// 搜索路径下的仓库
    pub fn search<'a, T: Iterator<Item = &'a Path>>(&self, entry: T, level: usize) -> GitRes {
        let mut git_res = GitRes::new();

        for path in entry {
            let res_info = match ResourceInfo::new(path.to_path_buf()) {
                Ok(res) => res,
                Err(e) => {
                    log::error!("{e}");
                    continue;
                }
            };

            let res = res_info
                .tree_with_cond(
                    level,
                    |p| p.is_dir(),
                    |p| {
                        let p = p.join(".git");
                        !p.is_dir()
                    },
                )
                .filter(|info| info.path().join(".git").is_dir());

            for info in res.iter() {
                match self.remote(info.path(), true) {
                    Ok(git_info) => {
                        if let Some(m) = info.metadata() {
                            match m.modified() {
                                Ok(m) => {
                                    git_res.add_git_info(&git_info.set_modified(m));
                                }
                                Err(e) => {
                                    log::error!(
                                        "get modified time failed in `{}`, due to {e}",
                                        path.display()
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        git_res.add_git_info(&GitInfo::from(info));
                        log::error!("{e}");
                    }
                }
            }
        }

        git_res
    }
}

impl From<CommonArgs> for Git {
    fn from(value: CommonArgs) -> Self {
        Self { common: value }
    }
}
