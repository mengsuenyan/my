use super::{CodeInfo, ResourceInfo, Resources};
use crate::{error::MyError, fs::LangInfo, ty::TableShow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt::Display,
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitInfo {
    name: String,
    path: PathBuf,
    url: Option<String>,
    modified: Option<String>,
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

        if let Some(modified) = other.modified.as_ref() {
            self.modified = Some(modified.to_string());
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

    pub fn set_url(mut self, url: &str) -> Self {
        self.url = Some(url.to_string());
        self
    }

    pub fn set_modified(mut self, modified_time: &str) -> Self {
        self.modified = Some(modified_time.to_string());
        self
    }

    pub fn set_code_info(mut self, code_info: CodeInfo) -> Self {
        self.code_info = Some(code_info);
        self
    }

    fn to_vec_string(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            format!("{}", self.path.display()),
            self.url.as_ref().cloned().unwrap_or_default(),
            self.modified.as_ref().cloned().unwrap_or_default(),
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
                Ok(m) => Some(format!(
                    "{}",
                    DateTime::<Utc>::from(m).format("%Y/%m/%d-%H:%M:%S")
                )),
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

        if let Some(modified) = self.modified.as_ref() {
            f.write_str(" | ")?;
            f.write_str(modified.as_str())?;
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GitRes {
    info: Vec<GitInfo>,
}

impl GitRes {
    pub fn new() -> Self {
        Self { info: vec![] }
    }

    pub fn add_git_info(&mut self, info: &GitInfo) {
        self.info.push(info.clone());
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

    pub fn clear(&mut self) {
        self.info.clear();
    }

    /// 去掉重复的条目, 以仓库路径为id键值
    pub fn reduce(&mut self) {
        let res = self.info.clone();
        self.clear();
        for item in res {
            if !self.info.iter().any(|info| info.path() == item.path()) {
                self.info.push(item);
            } else {
                log::info!("remove duplicate item\n{}", item)
            }
        }
    }

    /// 解析my.nu nullshell脚本生成的资源文件
    pub fn from_my_res(path: &Path) -> Result<Self, MyError> {
        if !path.is_file() {
            return Err(MyError::PathNotExist(format!(
                "`{}` is not exist",
                path.display()
            )));
        }

        let content = std::fs::read_to_string(path).map_err(|e| {
            MyError::JsonParseFailed(format!(
                "read `{}` to string failed due to {}",
                path.display(),
                e
            ))
        })?;

        let json = Value::from_str(&content).map_err(|e| {
            MyError::JsonParseFailed(format!(
                "parse `{}` to json failed due to {}",
                path.display(),
                e
            ))
        })?;

        let mut git_res = GitRes::new();
        if let Value::Array(json) = json {
            for val in json {
                let mut info = GitInfo::new(Path::new(val["path"].as_str().unwrap()));
                if let Some(url) = val["url"].as_str() {
                    if !url.is_empty() {
                        info = info.set_url(url);
                    }
                }

                if let Some(modified) = val["modified"].as_str() {
                    if !modified.is_empty() {
                        info = info.set_modified(modified);
                    }
                }

                if let Some(code) = val["info"].as_array() {
                    let mut code_info = CodeInfo::new();

                    for ele in code.iter() {
                        if let Value::Object(ele) = ele {
                            let mut lang = if let Some(s) = ele["language"].as_str() {
                                LangInfo::new(s)
                            } else {
                                continue;
                            };

                            if let Some(files) = ele["files"].as_u64() {
                                lang = lang.set_files(files as usize);
                            }

                            if let Some(code) = ele["code"].as_u64() {
                                lang = lang.set_codes(code as usize);
                            }

                            if let Some(comments) = ele["comments"].as_u64() {
                                lang = lang.set_comments(comments as usize);
                            }

                            if let Some(blanks) = ele["blanks"].as_u64() {
                                lang = lang.set_blanks(blanks as usize);
                            }

                            code_info.add_lang(lang);
                        }
                    }

                    if !code_info.is_empty() {
                        info = info.set_code_info(code_info);
                    }
                }

                git_res.add_git_info(&info);
            }
        } else {
            return Err(MyError::JsonParseFailed(format!(
                "`{}` content is not json array",
                path.display()
            )));
        }

        Ok(git_res)
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
        Self { info: vec![value] }
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
