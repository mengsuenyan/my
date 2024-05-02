use clap::{value_parser, Arg, ArgAction, Command};
use std::collections::HashSet;
use std::process::Command as StdCommand;
use std::{collections::VecDeque, path::PathBuf};
use url::Url;

use crate::fs::GitInfo;
use crate::{
    cmd::{Cmd, WorkingdirGuard},
    fs::GitRes,
};

use super::GitCmd;

pub struct CloneCmd<'a> {
    git_cmd: &'a GitCmd,
    pipe: Vec<String>,
    max_try: usize,
    res: GitRes,
}

impl<'a> CloneCmd<'a> {
    pub fn new(git_cmd: &'a GitCmd, pipe_str: Vec<String>, max_try: usize) -> Self {
        Self {
            res: git_cmd.open_res_file(),
            git_cmd,
            pipe: pipe_str,
            max_try,
        }
    }

    fn contain(&self, url: &str) -> bool {
        self.res.iter().any(|x| x.url() == Some(url))
    }

    fn find_reps(&self, url: &str) -> Vec<GitInfo> {
        self.res
            .iter()
            .filter(|x| x.url() == Some(url))
            .cloned()
            .collect()
    }

    fn clone_cmd(&self, target_dir: PathBuf, urls: Vec<Url>, max_try: usize) -> GitRes {
        let target_dir = target_dir.canonicalize().unwrap();
        let (mut git_res, mut urls, mut cnt) = (GitRes::new(), VecDeque::from(urls), 0);

        while let Some(url) = urls.pop_back() {
            let _guard = WorkingdirGuard::new(&self.git_cmd.cur_dir, target_dir.as_path());

            cnt += 1;
            log::info!("git clone {} into `{}`", url, target_dir.display());
            match GitCmd::git(StdCommand::new("git").arg("clone").arg(url.as_str())) {
                Ok(s) => {
                    cnt = 0;
                    log::info!("Ok. {s}");
                    if let Some(Some(p)) = url.path_segments().map(|p| p.last()) {
                        let path = target_dir.join(p.trim_end_matches(".git"));
                        match self.git_cmd.remote(&path, false) {
                            Ok(info) => git_res.add_git_info(&info),
                            Err(e) => {
                                log::error!("{e}");
                            }
                        }
                    } else {
                        log::warn!("cannot get basename from `{}`", url);
                    }
                }
                Err(e) => {
                    let e_str = format!("{e}");
                    if e_str.contains("already exists") {
                        log::warn!("{e}");
                        cnt = 0;
                    } else {
                        log::error!("{e_str}");
                        if cnt < max_try {
                            urls.push_front(url);
                        } else {
                            log::warn!("{} clone trying times exceed {}", url, max_try);
                            cnt = 0;
                        }
                    }
                }
            }

            if !urls.is_empty() {
                self.git_cmd.sleep();
            }
        }

        git_res
    }
}

impl<'a> Cmd for CloneCmd<'a> {
    const NAME: &'static str = "clone";

    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .about("git clone <TARGET> addrs")
            .arg(
                Arg::new("dir")
                    .value_name("TARGET DIR")
                    .long("dir")
                    .short('d')
                    .action(ArgAction::Set)
                    .required(false)
                    .value_parser(value_parser!(PathBuf))
                    .help("to specify the clone addr, default is current working directory"),
            )
            .arg(
                Arg::new("addr")
                    .value_name("ADDRs")
                    .action(ArgAction::Append)
                    .required(true)
                    .value_parser(value_parser!(String))
                    .help("git repository address"),
            )
            .arg(
                Arg::new("force")
                    .long("force")
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("force clone when the repo have existed"),
            )
    }

    fn run(&self, m: &clap::ArgMatches) {
        let target_dir = m
            .get_one::<PathBuf>("dir")
            .cloned()
            .unwrap_or_else(|| self.git_cmd.cur_dir.clone());

        let mut url_str = self.pipe.iter().collect::<HashSet<_>>();
        if let Some(url) = m.get_many::<String>("addr") {
            url.for_each(|url| {
                url_str.insert(url);
            });
        }

        let parse = |s: &str| match Url::parse(s) {
            Ok(url) => Some(url),
            Err(e) => {
                log::error!("`{}` parse as url failed, {e}", s);
                None
            }
        };

        let is_force = m.get_flag("force");
        let mut urls = Vec::with_capacity(url_str.len().min(1024));
        for s in url_str.iter() {
            if is_force || !self.contain(s.as_str()) {
                if let Some(url) = parse(s.as_str()) {
                    urls.push(url);
                }
            } else {
                let infos = self.find_reps(s.as_str());
                for info in infos {
                    if !info.path().exists() {
                        if let Some(url) = parse(s.as_str()) {
                            urls.push(url);
                        }
                    } else {
                        log::info!("{s} have existed in the {:?}", info.path());
                    }
                }
            }
        }

        let r = self.clone_cmd(target_dir, urls, self.max_try);
        println!("{}", r);
        self.git_cmd.update_res_file(&r);
    }
}
