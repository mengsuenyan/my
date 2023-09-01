pub trait Cmd {
    const NAME: &'static str;

    fn cmd(&self) -> Command;

    fn run(&self, m: &ArgMatches);
}

pub(self) struct WorkingdirGuard<'a> {
    pre: &'a Path,
}

impl<'a> WorkingdirGuard<'a> {
    fn new(pre: &'a Path, cur: &'a Path) -> Self {
        if let Err(e) = std::env::set_current_dir(&cur) {
            panic!("set current dir to `{}` failed, {e}", cur.display());
        }

        Self { pre }
    }
}

impl<'a> Drop for WorkingdirGuard<'a> {
    fn drop(&mut self) {
        if let Err(e) = std::env::set_current_dir(self.pre) {
            panic!("set current dir to `{}` failed, {e}", self.pre.display());
        }
    }
}

mod my_fs;
use std::path::Path;

use clap::{ArgMatches, Command};
pub use my_fs::MyFsCmd;

mod tokei;
pub use tokei::TokeiCmd;

mod git;
pub use git::GitCmd;
