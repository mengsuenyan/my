use std::path::Path;

pub struct WorkingdirGuard<'a> {
    pre: &'a Path,
}

impl<'a> WorkingdirGuard<'a> {
    pub fn new(pre: &'a Path, cur: &'a Path) -> anyhow::Result<Self> {
        if let Err(e) = std::env::set_current_dir(cur) {
            anyhow::bail!("set current dir to `{}` failed, {e}", cur.display());
        }

        Ok(Self { pre })
    }
}

impl<'a> Drop for WorkingdirGuard<'a> {
    fn drop(&mut self) {
        if let Err(e) = std::env::set_current_dir(self.pre) {
            panic!(
                "cannot recover to previous working directory `{}`, {e}",
                self.pre.display()
            );
        }
    }
}
