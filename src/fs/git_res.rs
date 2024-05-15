use super::{CodeInfo, ResourceInfo, Resources};
use crate::ty::TableShow;
use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    path::{Path, PathBuf},
    time::SystemTime,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitInfo {
    name: String,
    path: PathBuf,
    url: Option<String>,
    modified: Option<SystemTime>,
    code_info: Option<CodeInfo>,
}

impl GitInfo {
    pub fn new(path: &Path) -> Self {
        let path = path.to_path_buf();
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();

        Self {
            name,
            path,
            url: None,
            modified: None,
            code_info: None,
        }
    }

    pub fn update(&mut self, other: &GitInfo) {
        self.name.clear();
        self.name.push_str(&other.name);
        self.path.clear();
        self.path.clone_from(&other.path);
        if let Some(url) = other.url.as_ref() {
            self.url = Some(url.to_string());
        }

        if let Some(m) = other.modified {
            self.modified = Some(m);
        }

        if let Some(code) = other.code_info.as_ref() {
            self.code_info = Some(code.clone());
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn set_url(mut self, url: &str) -> Self {
        self.url = Some(url.to_string());
        self
    }

    pub fn set_modified(mut self, modified_time: SystemTime) -> Self {
        self.modified = Some(modified_time);
        self
    }

    pub fn modified(&self) -> Option<SystemTime> {
        self.modified
    }

    pub fn set_code_info(mut self, code_info: CodeInfo) -> Self {
        self.code_info = Some(code_info);
        self
    }

    fn systemtime_to_string(time: Option<SystemTime>) -> String {
        time.map(|x| format!("{}", DateTime::<Utc>::from(x).format("%Y/%m/%d-%H:%M:%S")))
            .unwrap_or_default()
    }

    fn to_vec_string(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            format!("{}", self.path.display()),
            self.url.as_ref().cloned().unwrap_or_default(),
            Self::systemtime_to_string(self.modified),
        ]
    }
}

impl From<ResourceInfo> for GitInfo {
    fn from(value: ResourceInfo) -> Self {
        Self::from(&value)
    }
}

impl From<&ResourceInfo> for GitInfo {
    fn from(value: &ResourceInfo) -> Self {
        let path = value.path().to_path_buf();
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let m = if let Some(m) = value.metadata() {
            match m.modified() {
                Ok(m) => Some(m),
                Err(e) => {
                    log::error!(
                        "get modified time failed in `{}`, due to {e}",
                        path.display()
                    );
                    None
                }
            }
        } else {
            None
        };

        Self {
            name,
            path,
            url: None,
            modified: m,
            code_info: None,
        }
    }
}

impl Display for GitInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)?;
        if let Some(url) = self.url.as_ref() {
            f.write_str(" | ")?;
            f.write_str(url.as_str())?;
        }

        f.write_str(" | ")?;
        f.write_fmt(format_args!("{}", self.path.display()))?;

        if let Some(modified) = self.modified {
            f.write_str(" | ")?;
            f.write_str(&Self::systemtime_to_string(Some(modified)))?;
        }

        Ok(())
    }
}

pub struct GitResIter<'a, GitInfo: 'a> {
    iter: std::slice::Iter<'a, GitInfo>,
}

impl<'a> Iterator for GitResIter<'a, GitInfo> {
    type Item = &'a GitInfo;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitRes {
    version: Version,
    info: Vec<GitInfo>,
}

impl Default for GitRes {
    fn default() -> Self {
        Self {
            version: GitRes::VERSION,
            info: vec![],
        }
    }
}

impl GitRes {
    const VERSION: Version = Version::new(0, 1, 0);

    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_git_info(&mut self, info: &GitInfo) {
        self.info.push(info.clone());
    }

    pub fn append_git_infos(&mut self, info: &[GitInfo]) {
        for x in info {
            self.add_git_info(x);
        }
    }

    pub fn iter(&self) -> GitResIter<'_, GitInfo> {
        GitResIter {
            iter: self.info.iter(),
        }
    }

    pub fn merge(&mut self, other: &GitRes) {
        for info in other.iter() {
            if self.info.iter().any(|ele| ele.path == info.path) {
                if let Some(ele) = self.info.iter_mut().find(|ele| ele.path == info.path) {
                    ele.update(info);
                };
            } else {
                self.info.push(info.clone());
            }
        }
    }

    pub fn delete(&mut self, path: &Path) {
        if let Some((idx, _)) = self
            .info
            .iter()
            .enumerate()
            .find(|info| info.1.path() == path)
        {
            log::info!("delete git info\n{}", self.info.remove(idx));
        }
    }

    pub fn exists(&self, path: &Path) -> bool {
        self.info.iter().any(|info| info.path() == path)
    }

    pub fn update_code_info(&mut self, path: &Path, code_info: CodeInfo) {
        if let Some(i) = self.info.iter_mut().find(|i| i.path() == path) {
            log::info!("update the `{}` code info", i.path().display());
            i.code_info = Some(code_info);
        }
    }

    pub fn to_vec(&self) -> Vec<GitInfo> {
        self.info.clone()
    }

    pub fn git_info_nums(&self) -> usize {
        self.info.len()
    }

    pub fn clear(&mut self) {
        self.info.clear();
    }

    /// 以仓库url为id键值, 检查重复的仓库并返回. 另, `self`删掉不存在的仓库.
    pub fn reduce(&mut self, is_check: bool) -> GitRes {
        let mut res: HashMap<Option<String>, Vec<GitInfo>> = HashMap::with_capacity(256);
        for item in self.iter() {
            res.entry(item.url.clone())
                .or_insert(Vec::with_capacity(1))
                .push(item.clone());
        }

        let mut dup = res
            .iter_mut()
            .filter(|(k, v)| k.is_none() || v.len() > 1)
            .collect::<HashMap<_, _>>();

        let mut res = Vec::new();
        res.append(&mut self.info);
        for info in res {
            if let Some(x) = dup.get_mut(&info.url) {
                if let Some(idx) = x.iter().enumerate().find(|x| x.1.path() == info.path()) {
                    if is_check && !info.path().exists() {
                        x.swap_remove(idx.0);
                        continue;
                    }
                }
            }

            if !is_check || info.path().exists() {
                self.info.push(info);
            }
        }

        let mut show = GitRes::new();
        for (_, v) in dup {
            if v.len() > 1 {
                show.append_git_infos(v.as_slice());
            }
        }
        show
    }
}

impl TableShow for GitRes {
    const COLS: usize = 5;

    fn head() -> Vec<String> {
        vec!["index", "name", "path", "url", "modified"]
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn cols(&self) -> Vec<(String, Vec<String>)> {
        let mut res = (0..Self::COLS).map(|_| vec![]).collect::<Vec<_>>();

        if let Some(v) = res.first_mut() {
            (0..self.info.len()).for_each(|idx| v.push(format!("{idx}")));
        }

        for ele in self.info.iter() {
            res.iter_mut()
                .skip(1)
                .zip(ele.to_vec_string().into_iter())
                .for_each(|(r, col)| {
                    r.push(col);
                });
        }

        Self::head().into_iter().zip(res).collect()
    }
}

impl Display for GitRes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.table().as_str())
    }
}

impl From<GitInfo> for GitRes {
    fn from(value: GitInfo) -> Self {
        Self {
            version: Self::VERSION,
            info: vec![value],
        }
    }
}

impl From<&GitInfo> for GitRes {
    fn from(value: &GitInfo) -> Self {
        Self::from(value.clone())
    }
}

impl<'a, T> From<T> for GitRes
where
    T: std::iter::Iterator<Item = &'a GitInfo>,
{
    fn from(value: T) -> Self {
        let mut res = Self::new();
        for info in value {
            res.add_git_info(info);
        }

        res
    }
}

impl From<ResourceInfo> for GitRes {
    fn from(value: ResourceInfo) -> Self {
        Self::from(&value)
    }
}

impl From<&ResourceInfo> for GitRes {
    fn from(value: &ResourceInfo) -> Self {
        Self::from(GitInfo::from(value))
    }
}

impl From<&Resources> for GitRes {
    fn from(value: &Resources) -> Self {
        let mut git_res = Self::new();
        for res in value.iter() {
            git_res.add_git_info(&GitInfo::from(res))
        }

        git_res
    }
}

impl From<Resources> for GitRes {
    fn from(value: Resources) -> Self {
        Self::from(&value)
    }
}
