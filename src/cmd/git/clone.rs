use std::{
    collections::{HashSet, VecDeque},
    io::BufRead,
    path::PathBuf,
    process::Command as StdCommand,
};

use clap::Args;
use url::Url;

use crate::{cmd::guard::WorkingdirGuard, fs::GitRes};

use super::Git;

#[derive(Args)]
#[command(about = r#"clone some git repositories to the specified path"#)]
pub struct CloneArgs {
    #[arg(value_name = "ADDRs", help = "the address may be a git repository")]
    addrs: Vec<String>,

    #[arg(
        short,
        long,
        help = r#"the directory to save be cloned git repository
default using current working direcotry"#
    )]
    odir: Option<PathBuf>,

    #[arg(
        long,
        help = "force clone when the repository have existed in the resource meta info"
    )]
    force: bool,
}

impl CloneArgs {
    fn parse_url(&self, pipe: Option<&[u8]>, git: &Git) -> Vec<Url> {
        let mut url = self.addrs.clone().into_iter().collect::<HashSet<_>>();
        if let Some(pipe) = pipe {
            for line in pipe.lines() {
                match line {
                    Ok(l) => {
                        url.insert(l);
                    }
                    Err(e) => {
                        log::error!("pipe data: {e}");
                    }
                }
            }
        }

        let parse = |s: &str| match Url::parse(s) {
            Ok(url) => Some(url),
            Err(e) => {
                log::error!("`{}` parse as url failed, {e}", s);
                None
            }
        };

        let git_res = git.open_res_file();
        let is_contain = |s: &str| git_res.iter().any(|x| x.url() == Some(s));

        let find_reps = |s: &str| {
            git_res
                .iter()
                .filter(|x| x.url() == Some(s))
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut urls = Vec::with_capacity(url.len().min(1024));
        for s in url {
            if self.force || !is_contain(s.as_str()) {
                if let Some(url) = parse(s.as_str()) {
                    urls.push(url);
                }
            } else {
                let infos = find_reps(s.as_str());
                if !infos.iter().any(|x| x.path().exists()) {
                    if let Some(url) = parse(s.as_str()) {
                        urls.push(url);
                    }
                } else {
                    log::info!(
                        "{s} have existed in the one of {:?}",
                        infos.iter().map(|x| x.path()).collect::<Vec<_>>()
                    );
                }
            }
        }

        urls
    }

    pub fn exe(self, pipe: Option<&[u8]>, git: Git) {
        let urls = self.parse_url(pipe, &git);

        let cur_dir = Git::cur_dir().unwrap();
        let odir = self.odir.unwrap_or_else(|| cur_dir.clone());

        assert!(odir.is_dir(), "{} is not directory", odir.display());
        let odir = odir.canonicalize().unwrap();

        let (mut git_res, mut urls, mut cnt) = (GitRes::new(), VecDeque::from(urls), 0);

        while let Some(url) = urls.pop_back() {
            let _guard = match WorkingdirGuard::new(&cur_dir, odir.as_path()) {
                Ok(x) => x,
                Err(e) => {
                    log::error!("{e}");
                    continue;
                }
            };

            cnt += 1;
            log::info!("git clone {} into `{}`", url, odir.display());
            match Git::git(StdCommand::new("git").arg("clone").arg(url.as_str())) {
                Ok(s) => {
                    cnt = 0;
                    log::info!("Ok. {s}");
                    if let Some(Some(p)) = url.path_segments().map(|p| p.last()) {
                        let path = odir.join(p.trim_end_matches(".git"));
                        match git.remote(&path, false) {
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
                        if cnt < git.max_try() {
                            urls.push_front(url);
                        } else {
                            log::warn!("{} clone trying times exceed {}", url, git.max_try());
                            cnt = 0;
                        }
                    }
                }
            }

            if !urls.is_empty() {
                git.sleep();
            }
        }
    }
}
