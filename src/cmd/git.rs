use chrono::{DateTime, Utc};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use regex::Regex;
use std::cell::Cell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::Duration;
use url::Url;

use crate::fs::{GitInfo, GitRes, ResourceInfo};
use crate::{cmd::WorkingdirGuard, error::MyError};

use super::Cmd;

pub struct GitCmd {
    cur_dir: PathBuf,
    // 每次clone, update后的暂停的最大时间
    sleep: Cell<u64>,
    config_path: PathBuf,
    config_backup_path: PathBuf,
}

impl GitCmd {
    pub fn new() -> Result<Self, MyError> {
        let Some(mut path) = home::home_dir() else {
            panic!("cannot get home dir");
        };

        path.push(".config");
        path.push("my");
        if !path.is_dir() {
            std::fs::create_dir_all(path.as_path()).unwrap();
        }

        let mut backup = path.clone();
        backup.push(".git.res.backup");
        path.push("git.res");

        Ok(GitCmd {
            cur_dir: std::env::current_dir()
                .map_err(|e| MyError::ChangeDirFailed(format!("{e}")))?,
            sleep: Cell::new(60),
            config_path: path,
            config_backup_path: backup,
        })
    }

    pub fn open_res_file(&self) -> GitRes {
        if self.config_path.is_file() {
            let content = std::fs::read_to_string(self.config_path.as_path()).unwrap();
            serde_json::from_str::<GitRes>(&content).unwrap()
        } else {
            GitRes::new()
        }
    }

    // 更新资源记录文件
    pub fn update_res_file(&self, git_res: &GitRes) {
        let mut res = self.open_res_file();
        res.merge(git_res);
        self.write_res_file(&res);
    }

    pub fn write_res_file(&self, git_res: &GitRes) {
        let new_content = serde_json::to_string_pretty(&git_res).unwrap();

        match std::fs::write(self.config_path.as_path(), new_content.as_bytes()) {
            Ok(_) => {
                std::fs::copy(
                    self.config_path.as_path(),
                    self.config_backup_path.as_path(),
                )
                .unwrap();
            }
            Err(e) => {
                std::fs::copy(
                    self.config_backup_path.as_path(),
                    self.config_path.as_path(),
                )
                .unwrap();
                panic!("{e}");
            }
        }
    }

    fn sleep(&self) {
        let s = rand::random::<u64>() % self.sleep.get();
        std::thread::sleep(Duration::from_secs(s));
    }

    fn git(cmd: &mut StdCommand) -> Result<String, MyError> {
        let output = cmd.output().unwrap();

        if !output.status.success() {
            Err(MyError::GitFailed(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        } else {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    }

    fn remote_cmd(&self, path: &[PathBuf]) -> GitRes {
        let mut git_res = GitRes::new();
        for p in path.iter() {
            match self.remote(p, false) {
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

    fn res_cmd(&self, path: &[PathBuf], level: usize) -> GitRes {
        let mut git_res = GitRes::new();

        for path in path.iter() {
            let res_info = match ResourceInfo::new(path.clone()) {
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
                                    let s = format!(
                                        "{}",
                                        DateTime::<Utc>::from(m).format("%Y/%m/%d-%H:%M:%S")
                                    );
                                    git_res.add_git_info(&git_info.set_modified(s.as_str()));
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

    /// git remote -v获取仓库地址
    fn remote(&self, path: &Path, is_only_url: bool) -> Result<GitInfo, MyError> {
        let _guard = WorkingdirGuard::new(&self.cur_dir, path);
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
                                    return Ok(git_info.set_url(s.as_str()).set_modified(
                                        format!(
                                            "{}",
                                            DateTime::<Utc>::from(m).format("%Y/%m/%d-%H:%M:%S")
                                        )
                                        .as_str(),
                                    ));
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

        Err(MyError::GitNotFoundAddr(format!(
            "addr {s} not found in the `{}`",
            path.display()
        )))
    }

    fn update_cmd(&self, path: &[PathBuf], level: usize, max_try: usize) -> GitRes {
        let mut git_res = self.res_cmd(path, level);
        let mut infos = VecDeque::from(git_res.to_vec());
        let update_config_per_items = std::env::var("MY_GIT_UPDATE_ITEMS")
            .unwrap_or("1".to_string())
            .parse::<usize>()
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

    fn clone_cmd(&self, target_dir: PathBuf, urls: Vec<Url>, max_try: usize) -> GitRes {
        let target_dir = target_dir.canonicalize().unwrap();
        let (mut git_res, mut urls, mut cnt) = (GitRes::new(), VecDeque::from(urls), 0);

        while let Some(url) = urls.pop_back() {
            let _guard = WorkingdirGuard::new(&self.cur_dir, target_dir.as_path());

            cnt += 1;
            log::info!("git clone {} into `{}`", url, target_dir.display());
            match Self::git(StdCommand::new("git").arg("clone").arg(url.as_str())) {
                Ok(s) => {
                    cnt = 0;
                    log::info!("Ok. {s}");
                    if let Some(Some(p)) = url.path_segments().map(|p| p.last()) {
                        let path = target_dir.join(p.trim_end_matches(".git"));
                        match self.remote(&path, false) {
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
                self.sleep();
            }
        }

        git_res
    }

    fn delete(&self, path: &Path) {
        let path = path.canonicalize().unwrap();
        assert!(path != Path::new("/"));
        assert!(home::home_dir().map(|home| home == path) != Some(true));

        let mut git_res = self.open_res_file();

        if !git_res.exists(path.as_path()) {
            log::error!("`{}` is not in the git resources", path.display());
            return;
        }

        std::fs::remove_dir_all(path.as_path()).unwrap();

        git_res.delete(path.as_path());

        self.write_res_file(&git_res);
    }

    fn copy(&self, from: &Path, to: &Path) {
        let (from, mut to) = (from.canonicalize().unwrap(), to.canonicalize().unwrap());
        match Self::git(
            StdCommand::new("cp")
                .arg("-rfv")
                .arg(format!("{}", from.display()))
                .arg(format!("{}", to.display())),
        ) {
            Ok(s) => {
                log::info!("{s}");
                to.push(from.file_name().unwrap());
                let git_res = self.remote_cmd(&[to]);
                self.update_res_file(&git_res);
            }
            Err(e) => {
                panic!("{e}");
            }
        }
    }

    fn mv(&self, from: &Path, to: &Path) {
        self.copy(from, to);
        self.delete(from);
    }

    fn reduce(&self) {
        let mut res = self.open_res_file();
        res.reduce();
        self.write_res_file(&res);
    }

    fn temp_cmd(&self, m: &ArgMatches) -> GitRes {
        let rules = m.get_many::<String>("rule").unwrap().collect::<Vec<_>>();
        let (mut finds, res) = (GitRes::new(), self.open_res_file());
        for info in res.iter() {
            let path = info.path();
            if rules.iter().any(|s| path.join(s.as_str()).is_dir()) {
                finds.add_git_info(info);
            }
        }

        finds
    }

    fn search_cmd(&self, m: &ArgMatches) -> GitRes {
        let name = m.get_one::<String>("name").unwrap();
        let res = self.open_res_file();

        let re = Regex::new(name.as_str()).unwrap();

        res.iter().filter(|s| re.is_match(s.name())).into()
    }
}

impl Cmd for GitCmd {
    const NAME: &'static str = "git";

    fn cmd() -> clap::Command {
        Command::new(Self::NAME)
            .about("git operation")
            .arg(
                Arg::new("dirs")
                    .value_name("DIRs")
                    .action(ArgAction::Append)
                    .value_parser(value_parser!(PathBuf))
                    .required(false)
                    .help("to specify the dir path"),
            )
            .arg(
                Arg::new("pipe")
                    .short('p')
                    .long("pipe")
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .help("using pipe to transform data"),
            )
            .arg(
                Arg::new("sleep")
                    .value_name("SECOND")
                    .long("sleep")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(u64))
                    .default_value("10")
                    .required(false)
                    .help("to specify the max sleep times"),
            )
            .arg(
                Arg::new("addr")
                    .long("addr")
                    .action(ArgAction::SetTrue)
                    .required(false)
                    .conflicts_with_all(["res", "update"])
                    .help("get the git repository address"),
            )
            .arg(
                Arg::new("res")
                    .value_name("LEVEL")
                    .long("res")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(usize))
                    .required(false)
                    .conflicts_with_all(["addr", "update"])
                    .help("search git repositories with specified levle"),
            )
            .arg(
                Arg::new("update")
                    .value_name("LEVEL")
                    .long("update")
                    .action(ArgAction::Set)
                    .required(false)
                    .value_parser(value_parser!(usize))
                    .conflicts_with_all(["addr", "res"])
                    .help("search git repositories with specified levle"),
            )
            .arg(
                Arg::new("max-try")
                    .long("max-try")
                    .action(ArgAction::Set)
                    .required(false)
                    .default_value("1")
                    .value_parser(value_parser!(usize))
                    .help("to specify the max try times when git operation failed"),
            )
            .arg(
                Arg::new("notty-prompt")
                .long("notty-prompt")
                .action(ArgAction::SetFalse)
                .required(false)
                .help("If this Boolean environment variable is enabled, git will not prompt on the terminal")
            )
            .subcommand(
                Command::new("clone")
                    .about("git clone <TARGET> addrs")
                    .arg(
                        Arg::new("dir")
                            .value_name("TARGET DIR")
                            .long("dir")
                            .short('d')
                            .action(ArgAction::Set)
                            .required(false)
                            .value_parser(value_parser!(PathBuf))
                            .help(
                                "to specify the clone addr, default is current working directory",
                            ),
                    )
                    .arg(
                        Arg::new("addr")
                            .value_name("ADDRs")
                            .action(ArgAction::Append)
                            .required(true)
                            .value_parser(value_parser!(String))
                            .help("git repository address"),
                    ),
            )
            .subcommand(
                Command::new("cp")
                    .about("copy git repository from path to another path")
                    .arg(
                        Arg::new("from")
                            .long("from")
                            .short('f')
                            .action(ArgAction::Set)
                            .required(true)
                            .value_parser(value_parser!(PathBuf))
                            .help("to specify the from directory"),
                    )
                    .arg(
                        Arg::new("to")
                            .long("to")
                            .short('t')
                            .action(ArgAction::Set)
                            .required(true)
                            .value_parser(value_parser!(PathBuf))
                            .help("to specify the to directory"),
                    ),
            )
            .subcommand(
                Command::new("mv")
                    .about("mv git repository from path to another path")
                    .arg(
                        Arg::new("dirs")
                            .value_names(["FROM", "TO"])
                            .required(true)
                            .action(ArgAction::Append)
                            .value_parser(value_parser!(PathBuf))
                            .help("mv git repository from FROM to TO directory"),
                    ),
            )
            .subcommand(
                Command::new("rm").about("rm git repository").arg(
                    Arg::new("dir")
                        .value_name("DIR")
                        .action(ArgAction::Set)
                        .required(true)
                        .value_parser(value_parser!(PathBuf))
                        .help("to specify the deleted directory"),
                ),
            )
            .subcommand(Command::new("open").about("open git resource file"))
            .subcommand(
                Command::new("reduce").about("remove duplicate entries in the git resource file"),
            )
            .subcommand(
                Command::new("temp")
                    .about("find the repository that have temporary directory")
                    .arg(
                        Arg::new("rule")
                            .value_name("RULEs")
                            .action(ArgAction::Append)
                            .required(false)
                            .default_values(["target", "node_modules", "build"])
                            .value_parser(value_parser!(String))
                            .help("to specify the temporary directory"),
                    ),
            )
            .subcommand(
                Command::new("search")
                    .about("search specified repository in the git resources")
                    .arg(
                        Arg::new("name")
                            .value_name("NAME")
                            .action(ArgAction::Set)
                            .required(true)
                            .value_parser(value_parser!(String))
                            .help("to specify the repository name"),
                    ),
            )
    }

    fn run(&self, m: &clap::ArgMatches) {
        let (mut path, mut pipe_str) = (Vec::new(), Vec::new());

        if !m.get_flag("notty-prompt") {
            std::env::set_var("GIT_TERMINAL_PROMPT", "false");
            log::info!("set GIT_TERMINAL_PROMPT=false");
        }

        if m.get_flag("pipe") {
            std::io::stdin().lines().for_each(|line| match line {
                Ok(line) => {
                    pipe_str.push(line.clone());
                    path.push(PathBuf::from(line));
                }
                Err(e) => {
                    log::error!("{}", e);
                }
            });
        }

        if let Some(p) = m.get_many::<PathBuf>("dirs") {
            p.for_each(|p| path.push(p.clone()));
        }

        let path = path
            .into_iter()
            .filter(|p| {
                if !p.is_dir() {
                    log::error!("`{}` is not directory", p.display());
                    false
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();

        if let Some(sleep) = m.get_one::<u64>("sleep").copied() {
            assert!(sleep > 1, "sleep second must great than 1 seconds");
            self.sleep.set(sleep);
        }

        if m.get_flag("addr") {
            let r = self.remote_cmd(&path);
            println!("{}", r);
            self.update_res_file(&r);
        }

        if let Some(lvl) = m.get_one::<usize>("res").copied() {
            let r = self.res_cmd(&path, lvl);
            println!("{}", r);
            self.update_res_file(&r);
        }

        let max_try = m.get_one::<usize>("max-try").copied().unwrap_or(1);
        if let Some(lvl) = m.get_one::<usize>("update").copied() {
            let r = self.update_cmd(&path, lvl, max_try);
            self.update_res_file(&r);
        }

        match m.subcommand() {
            Some(("clone", m)) => {
                let target_dir = m
                    .get_one::<PathBuf>("dir")
                    .cloned()
                    .unwrap_or_else(|| self.cur_dir.clone());

                let mut url_str = pipe_str.clone();
                if let Some(url) = m.get_many::<String>("addr") {
                    url.for_each(|url| url_str.push(url.clone()));
                }

                let mut urls = vec![];
                for s in url_str.iter() {
                    match Url::parse(s.as_str()) {
                        Ok(url) => {
                            urls.push(url);
                        }
                        Err(e) => {
                            log::error!("`{}` parse as url failed, {e}", s);
                        }
                    }
                }

                let r = self.clone_cmd(target_dir, urls, max_try);
                println!("{}", r);
                self.update_res_file(&r);
            }
            Some(("cp", m)) => {
                let from = m.get_one::<PathBuf>("from").unwrap();
                let to = m.get_one::<PathBuf>("to").unwrap();
                self.copy(from.as_path(), to.as_path());
            }
            Some(("mv", m)) => {
                let dirs = m.get_many::<PathBuf>("dirs").unwrap().collect::<Vec<_>>();
                self.mv(dirs[0].as_path(), dirs[1].as_path());
            }
            Some(("rm", m)) => {
                let path = m.get_one::<PathBuf>("dir").unwrap();
                self.delete(path.as_path());
            }
            Some(("open", _m)) => {
                println!("{}", self.open_res_file());
            }
            Some(("reduce", _m)) => {
                self.reduce();
            }
            Some(("temp", m)) => {
                println!("{}", self.temp_cmd(m));
            }
            Some(("search", m)) => {
                println!("{}", self.search_cmd(m));
            }
            Some((name, _)) => {
                panic!("unsupport for the {}", name);
            }
            None => {}
        }

        // let r = GitRes::from_my_res(
        //     home::home_dir()
        //         .unwrap()
        //         .as_path()
        //         .join(Path::new("github/resources.json"))
        //         .as_path(),
        // )
        // .unwrap();
        // self.update_res_file(&r);
    }
}
