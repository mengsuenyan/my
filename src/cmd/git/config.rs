use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GitConfig {
    pub meta_info: PathBuf,
    pub meta_info_backup: PathBuf,
    pub save_per_items: usize,
}

impl Default for GitConfig {
    fn default() -> Self {
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

        Self {
            meta_info: path,
            meta_info_backup: backup,
            save_per_items: 10,
        }
    }
}
