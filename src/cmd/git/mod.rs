use std::{cell::Cell, path::PathBuf};

pub struct GitCmd {
    cur_dir: PathBuf,
    // 每次clone, update后的暂停的最大时间
    sleep: Cell<u64>,
    config_path: PathBuf,
    config_backup_path: PathBuf,
}

mod cmd;

mod update;

mod clone;
