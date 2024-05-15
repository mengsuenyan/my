use crate::fs::{ResourceInfo, Resources};
use crate::log_error;
use crate::ty::TableShow;
use anyhow::Error;
use clap::{builder::PossibleValuesParser, Args};
use std::path::Path;

#[derive(Args)]
pub struct ShowArgs {
    #[arg(group = "show", long, help = "list the path")]
    list: bool,
    #[arg(group = "show", long, help = "tree the path")]
    tree: bool,

    #[arg(long, default_value = "1", help = "show directory level", value_parser = clap::value_parser!(u16).range(1..))]
    level: u16,

    #[arg(long, help = "show the result as table")]
    table: bool,

    #[arg(long = "type", value_name = "TYPE", value_parser = PossibleValuesParser::new(["dir", "file", "symlink", "all"]))]
    #[arg(default_value = "all", help = "the type of file to show")]
    p_type: String,
}

impl ShowArgs {
    pub fn exe(&self, path: &Path) {
        let Some(res_info) = log_error(ResourceInfo::new(path.to_path_buf()).map_err(Error::from))
        else {
            return;
        };
        println!("{}", path.display());

        if self.tree {
            let filter: Box<dyn Fn(&Path) -> bool> = match self.p_type.as_str() {
                "file" => Box::new(|p| p.is_file()),
                "dir" => Box::new(|p| p.is_dir()),
                "symlink" => Box::new(|p| p.is_symlink()),
                "all" => Box::new(|_| true),
                _ => unreachable!("not support file type `{}`", self.p_type),
            };

            let res = res_info.tree_with_cond(self.level as usize, filter, |_| true);
            self.show(&res);
        }

        if self.list {
            let res = match self.p_type.as_str() {
                "file" => res_info.list().filter(|x| x.is_file()),
                "dir" => res_info.list().filter(|x| x.is_dir()),
                "symlink" => res_info.list().filter(|x| x.is_symlink()),
                "all" => res_info.list().filter(|_| true),
                _ => unreachable!("not support file type: `{}`", self.p_type),
            };

            self.show(&res);
        }
    }

    fn show(&self, res: &Resources) {
        if self.table {
            println!("{}", res.table());
        } else {
            println!("{}", res);
        }
    }
}
