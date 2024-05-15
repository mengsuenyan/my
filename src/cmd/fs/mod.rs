mod show;

use crate::cmd::git::GitCmd;
use clap::{Args, Subcommand};
use show::ShowArgs;
use std::path::PathBuf;

#[derive(Args)]
#[command(about = "file system")]
pub struct FsArgs {
    dir: PathBuf,

    #[command(subcommand)]
    sub_cmd: Option<FsSubArgs>,
}

#[derive(Subcommand)]
pub enum FsSubArgs {
    Show(ShowArgs),
}

impl FsArgs {
    pub fn exe(self, pipe: Option<&[u8]>) {
        let dirs = GitCmd::parse_pipe_to_path(pipe);

        if let Some(sub_cmd) = self.sub_cmd {
            for p in dirs
                .iter()
                .map(|x| x.as_path())
                .chain(std::iter::once(self.dir.as_path()))
            {
                match &sub_cmd {
                    FsSubArgs::Show(a) => a.exe(p),
                }
            }
        }
    }
}
