use std::{
    io::BufRead,
    path::{Path, PathBuf},
    vec,
};

use clap::{Args, Subcommand};

use self::{
    base::{AddrArgs, CheckArgs, CopyArgs, DeleteArgs},
    clone::CloneArgs,
    find::{FindArgs, SearchArgs},
    update::UpdateArgs,
};

pub mod base;
pub mod clone;
pub mod config;
pub mod find;
pub mod update;

mod git_;
mod tokei;

pub use git_::Git;

#[derive(Args, Clone, PartialEq, Eq)]
struct CommonArgs {
    #[arg(long, default_value = "10", help = "the max sleep second times")]
    sleep: u64,

    #[arg(
        long = "max-try",
        default_value = "1",
        help = "the max try times when git operation failed"
    )]
    max_try: usize,

    #[arg(long = "notty-prompt", help = "git not prompt input on the terminal")]
    notty_prompt: bool,
}

#[derive(Args)]
#[command(name = "git")]
#[command(about = "git assitant command")]
pub struct GitCmd {
    #[command(subcommand)]
    cmd: GitSubCmd,

    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Subcommand)]
pub enum GitSubCmd {
    #[command(name = "update", alias = "u")]
    Update(UpdateArgs),
    #[command(name = "clone", alias = "c")]
    Clone(CloneArgs),
    #[command(name = "copy", alias = "cp")]
    Copy(CopyArgs),
    #[command(name = "move", alias = "mv")]
    #[command(about = "move git repository")]
    Move(CopyArgs),
    #[command(name = "addr")]
    Addr(AddrArgs),
    #[command(name = "delete", alias = "rm")]
    Delete(DeleteArgs),
    #[command(name = "check")]
    Check(CheckArgs),
    #[command(name = "open", about = "open the git resources file")]
    Open,
    #[command(name = "find")]
    Find(FindArgs),
    #[command(name = "search")]
    Search(SearchArgs),
    Tokei(tokei::GitTokeiArgs),
}

impl GitCmd {
    pub fn parse_pipe_to_path(pipe: Option<&[u8]>) -> Vec<PathBuf> {
        let mut path = vec![];
        if let Some(p) = pipe {
            for line in p.lines() {
                match line {
                    Ok(line) => path.push(Path::new(&line).to_path_buf()),
                    Err(e) => {
                        log::error!("pipe data: {:?}", e);
                    }
                }
            }
        }

        path
    }

    pub fn exe(self, pipe: Option<&[u8]>) {
        if self.common.notty_prompt {
            std::env::set_var("GIT_TERMINAL_PROMPT", "false");
            log::info!("set GIT_TERMINAL_PROMPT=false");
        }

        let git = self.common.into();

        match self.cmd {
            GitSubCmd::Update(a) => a.exe(Self::parse_pipe_to_path(pipe), git),
            GitSubCmd::Clone(a) => a.exe(pipe, git),
            GitSubCmd::Copy(a) => {
                let _ = a.exe(Self::parse_pipe_to_path(pipe), git);
            }
            GitSubCmd::Move(a) => {
                let from_dirs = a.exe(Self::parse_pipe_to_path(pipe), git.clone());
                let d = DeleteArgs::new(from_dirs, true);
                d.exe(vec![], git);
            }
            GitSubCmd::Addr(a) => a.exe(Self::parse_pipe_to_path(pipe), git),
            GitSubCmd::Delete(a) => a.exe(Self::parse_pipe_to_path(pipe), git),
            GitSubCmd::Check(a) => a.exe(git),
            GitSubCmd::Open => {
                let res = git.open_res_file();
                println!("{}", res);
            }
            GitSubCmd::Find(a) => a.exe(pipe, git),
            GitSubCmd::Search(a) => a.exe(Self::parse_pipe_to_path(pipe), git),
            GitSubCmd::Tokei(a) => a.exe(Self::parse_pipe_to_path(pipe), git),
        }
    }
}
