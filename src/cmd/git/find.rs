use std::path::PathBuf;

use chrono::{DateTime, Utc};
use clap::Args;
use regex::Regex;

use crate::fs::{GitInfo, GitRes};

use super::Git;

#[derive(Args)]
#[command(
    about = r#"find repository that have be collected in the local resource
find((PIPE || POS) && name && url && before && after)"#
)]
pub struct FindArgs {
    #[arg(
        value_name = "REGEX",
        help = "search all repositorires to match the REGEX in name/path/url..."
    )]
    condition: Option<Regex>,
    #[arg(long, value_name = "REGEX", help = "search by the name")]
    name: Option<Regex>,
    #[arg(long, value_name = "REGEX", help = "search by the path")]
    path: Option<Regex>,
    #[arg(long, value_name = "REGEX", help = "search by the url")]
    url: Option<Regex>,
    #[arg(
        long,
        value_name = "DATETIME",
        help = r#"search before the DATETIME(RFC3339)
eg: 2023-08-08T08:08:08Z"#
    )]
    before: Option<DateTime<Utc>>,
    #[arg(
        long,
        value_name = "DATETIME",
        help = "search after the DATETIME(RFC3339)"
    )]
    after: Option<DateTime<Utc>>,
}

#[derive(Args)]
#[command(about = "search repositories in the specified direcotry with level depth")]
pub struct SearchArgs {
    #[arg(value_name = "DIRs")]
    #[arg(help = "if DIRs and PIPE is empty that will search in the current working direcotry")]
    dirs: Vec<PathBuf>,

    #[arg(long, default_value = "1", help = "search level depth")]
    level: usize,
}

impl FindArgs {
    fn find_all(regex: &Regex, in_res: &[GitInfo], out_res: &mut Vec<GitInfo>) {
        for info in in_res {
            if regex.is_match(info.name()) {
                out_res.push(info.clone());
                continue;
            }

            if let Some(path) = info.path().to_str() {
                if regex.is_match(path) {
                    out_res.push(info.clone());
                    continue;
                }
            }

            if let Some(url) = info.url() {
                if regex.is_match(url) {
                    out_res.push(info.clone());
                    continue;
                }
            }
        }
    }

    pub fn exe(self, pipe: Option<&[u8]>, git: Git) {
        let mut in_res = git.open_res_file().to_vec();
        let mut out_res = Vec::with_capacity(in_res.len());

        if let Some(pipe) = pipe {
            let s = String::from_utf8(pipe.to_vec()).unwrap();
            let regex = Regex::new(&s).unwrap();
            Self::find_all(&regex, in_res.as_slice(), &mut out_res);
            in_res.clear();
            (in_res, out_res) = (out_res, in_res)
        }

        if let Some(regex) = self.condition {
            Self::find_all(&regex, in_res.as_slice(), &mut out_res);
            in_res.clear();
            (in_res, out_res) = (out_res, in_res);
        }

        if let Some(regex) = self.name {
            for info in in_res.iter() {
                if regex.is_match(info.name()) {
                    out_res.push(info.clone());
                }
            }
            in_res.clear();
            (in_res, out_res) = (out_res, in_res);
        }

        if let Some(regex) = self.path {
            for info in in_res.iter() {
                if let Some(path) = info.path().to_str() {
                    if regex.is_match(path) {
                        out_res.push(info.clone());
                    }
                }
            }
            in_res.clear();
            (in_res, out_res) = (out_res, in_res);
        }

        if let Some(regex) = self.url {
            for info in in_res.iter() {
                if let Some(url) = info.url() {
                    if regex.is_match(url) {
                        out_res.push(info.clone());
                    }
                }
            }
            in_res.clear();
            (in_res, out_res) = (out_res, in_res);
        }

        if let Some(before) = self.before {
            for info in in_res.iter() {
                if let Some(t) = info.modified() {
                    let d = DateTime::<Utc>::from(t);
                    if d <= before {
                        out_res.push(info.clone());
                    }
                }
            }
            in_res.clear();
            (in_res, out_res) = (out_res, in_res);
        }

        if let Some(after) = self.after {
            for info in in_res.iter() {
                if let Some(t) = info.modified() {
                    let d = DateTime::<Utc>::from(t);
                    if d >= after {
                        out_res.push(info.clone());
                    }
                }
            }
            in_res.clear();
            in_res = out_res;
        }

        let res = GitRes::from(in_res.iter());
        println!("{}", res);
    }
}

impl SearchArgs {
    pub fn exe(self, pipe: Vec<PathBuf>, git: Git) {
        let res = if pipe.is_empty() && self.dirs.is_empty() {
            let cur_dir = Git::cur_dir().unwrap();
            git.search(std::iter::once(cur_dir.as_path()), self.level)
        } else {
            git.search(
                pipe.iter().chain(self.dirs.iter()).map(|x| x.as_path()),
                self.level,
            )
        };

        git.update_res_file(&res);
        println!("{}", res);
    }
}
