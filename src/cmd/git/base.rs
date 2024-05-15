use clap::Args;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use crate::fs::{GitInfo, GitRes};

use super::Git;

#[derive(Args)]
#[command(about = "get git repository addr")]
pub struct AddrArgs {
    #[arg(value_name = "DIRs")]
    dirs: Vec<PathBuf>,
}

#[derive(Args)]
#[command(about = "copy git repositry")]
pub struct CopyArgs {
    #[arg(value_name = "FROMs", required = true)]
    from: Vec<PathBuf>,
    #[arg(value_name = "TO")]
    to: PathBuf,

    #[arg(long, help = "force copy if the FROM in the TO")]
    force: bool,

    #[arg(long, help = "verbose output")]
    verbose: bool,
}

#[derive(Args)]
#[command(about = "delete git repository")]
pub struct DeleteArgs {
    #[arg(value_name = "DIRs")]
    dirs: Vec<PathBuf>,

    #[arg(long, help = "force delete if the DIR is not git repository")]
    force: bool,
}

#[derive(Args)]
#[command(about = "check git resource")]
pub struct CheckArgs {
    #[arg(long, help = "remove non-exists repository")]
    rne: bool,

    #[arg(long, group = "exclude", help = "show duplicate repositories")]
    duplicate: bool,

    #[arg(long, group = "exclude")]
    #[arg(help = "show repositories that have temporay directory")]
    temp: bool,

    #[arg(long = "temp-rules", default_values = ["target", "node_modules", "build"])]
    temp_rules: Vec<String>,
}

impl CopyArgs {
    // 返回copy成功的路径
    pub fn exe(self, pipe: Vec<PathBuf>, git: Git) -> Vec<PathBuf> {
        let from = Git::merge_path(&pipe, &self.from);
        let from_len = from.len();

        assert!(!from.is_empty(), "no <FROM> directories");
        assert!(self.to.is_dir(), "{} is not direcotyr", self.to.display());
        let (git, to, is_force, is_verbose) = (&git, self.to.as_path(), self.force, self.verbose);

        let git_res = from
            .into_par_iter()
            .map(move |f| {
                let mut cmd = StdCommand::new("cp");
                let mut cmd = cmd.arg("-r");
                if is_force {
                    cmd = cmd.arg("-f");
                }
                if is_verbose {
                    cmd = cmd.arg("-v");
                }
                cmd.arg(format!("{}", f.display()))
                    .arg(format!("{}", to.display()));
                match Git::git(cmd) {
                    Ok(s) => {
                        log::info!("{s}");
                        let Some(name) = f.file_name() else {
                            log::error!("{} cannot get filename", f.display());
                            return (GitRes::new(), vec![f.to_path_buf()]);
                        };

                        let res = match git.remote(to.join(name).as_path(), false) {
                            Ok(x) => GitRes::from(x),
                            Err(e) => {
                                log::error!("{e}");
                                GitRes::new()
                            }
                        };

                        (res, vec![f.to_path_buf()])
                    }
                    Err(e) => {
                        log::error!("{e}");
                        (GitRes::new(), vec![])
                    }
                }
            })
            .reduce(
                || (GitRes::new(), Vec::with_capacity(from_len)),
                |mut x, y| {
                    x.0.merge(&y.0);
                    x.1.extend_from_slice(y.1.as_slice());
                    x
                },
            );

        git.update_res_file(&git_res.0);

        git_res.1
    }
}

impl AddrArgs {
    // 获取给定目录下的git仓库信息
    fn addrs<'a, T: Iterator<Item = &'a Path>>(itr: T, git: &Git) -> GitRes {
        let mut git_res = GitRes::new();

        for p in itr {
            match git.remote(p, false) {
                Ok(info) => {
                    git_res.add_git_info(&info);
                }
                Err(e) => {
                    log::error!("{e}");
                }
            }
        }

        git_res
    }

    pub fn exe(self, pipe: Vec<PathBuf>, git: Git) {
        let dirs = Git::merge_path(self.dirs.as_slice(), &pipe);
        let r = Self::addrs(dirs.iter().copied(), &git);
        println!("{}", r);
        git.update_res_file(&r);
    }
}

impl DeleteArgs {
    pub(super) fn new(dirs: Vec<PathBuf>, force: bool) -> Self {
        Self { dirs, force }
    }

    pub fn exe(self, pipe: Vec<PathBuf>, git: Git) {
        let mut dpath = vec![];

        for p in self.dirs.into_iter().chain(pipe) {
            if !p.exists() {
                log::warn!("`{}` not exists", p.display());
                continue;
            }

            let p = match p.canonicalize() {
                Ok(x) => x,
                Err(e) => {
                    log::error!("{e}");
                    continue;
                }
            };

            if p.components().count() < 2 {
                log::error!("cannot delete root directory `{}`", p.display());
                continue;
            }

            let is_git = p.join(".git").is_dir();
            if is_git || self.force {
                let e = if p.is_dir() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };

                if let Err(e) = e {
                    log::error!("delete `{}` failed, due to {e}", p.display());
                } else {
                    log::info!("delete `{}` success", p.display());
                    if p.is_dir() {
                        dpath.push(p);
                    }
                }
            } else if !self.force {
                log::warn!(
                    "{} is not git repository, use --force to force delete",
                    p.display()
                );
            }
        }

        let mut git_res = git.open_res_file();
        for p in dpath {
            git_res.delete(&p);
        }
        git.write_res_file(&git_res);
    }
}

impl CheckArgs {
    fn non_exists(&self, res: &GitRes) -> Vec<GitInfo> {
        res.iter().filter(|x| !x.path().exists()).cloned().collect()
    }

    fn duplicate(&self, res: &GitRes) -> Vec<GitInfo> {
        let mut dup = HashMap::with_capacity(res.git_info_nums().max(128));
        for item in res.iter() {
            dup.entry(item.url())
                .or_insert(Vec::with_capacity(1))
                .push(item.clone());
        }

        dup.into_iter()
            .filter(|x| x.1.len() > 1)
            .flat_map(|x| x.1.into_iter())
            .collect()
    }

    fn temp(&self, res: &GitRes, rules: &[String]) -> Vec<GitInfo> {
        res.iter()
            .filter(|x| rules.iter().any(|y| x.path().join(y.as_str()).is_dir()))
            .cloned()
            .collect()
    }

    pub fn exe(self, git: Git) {
        let mut res = git.open_res_file();

        if self.rne {
            let rne = self.non_exists(&res);
            println!("the above repositories doesn't exists");
            println!("{}", GitRes::from(rne.iter()));

            for x in rne {
                res.delete(x.path());
            }
            git.write_res_file(&res)
        }

        if self.duplicate {
            let dup = self.duplicate(&res);
            println!("the above repositories is duplicate");
            println!("{}", GitRes::from(dup.iter()));
        }

        if self.temp {
            let temp = self.temp(&res, &self.temp_rules);
            println!(
                "the above repositories have temporay directory: {:?}",
                self.temp_rules
            );
            println!("{}", GitRes::from(temp.iter()));
        }
    }
}
