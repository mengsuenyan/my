use std::{
    collections::{hash_map::DefaultHasher, HashMap, VecDeque},
    fmt::{Debug, Display, Write},
    fs::Metadata,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    rc::Rc,
};

use chrono::{DateTime, Utc};

use crate::{error::MyError, ty::TableShow};

#[derive(Clone, Debug)]
pub struct ResourceInfo {
    id: u64,
    parent_id: Option<u64>,
    level: usize,
    path: PathBuf,
    metadata: Option<Metadata>,
    // 子项目
    subs: Option<Vec<u64>>,
}

#[derive(Clone, Default)]
pub struct Resources {
    res_map: HashMap<u64, Vec<Rc<ResourceInfo>>>,
    res: Vec<Rc<ResourceInfo>>,
}

impl ResourceInfo {
    pub fn new(p: PathBuf) -> Result<Self, MyError> {
        if !p.exists() {
            return Err(MyError::PathNotExist(format!(
                "ths path `{}` not exist",
                p.display()
            )));
        }

        let p = if p.is_relative() {
            p.canonicalize()
                .map_err(|e| MyError::PathOtherErr(format!("{e}")))?
        } else {
            p
        };

        Ok(Self::new_uncheck(p))
    }

    fn new_uncheck(p: PathBuf) -> Self {
        let m = match p.metadata() {
            Ok(m) => Some(m),
            Err(e) => {
                log::error!(
                    "cannot read the metadata of the `{}` due to {}",
                    p.display(),
                    e
                );
                None
            }
        };

        Self {
            id: Self::hash_id(&p),
            parent_id: None,
            level: 0,
            path: p,
            metadata: m,
            subs: None,
        }
    }

    fn hash_id(p: &Path) -> u64 {
        let mut h = DefaultHasher::new();
        p.hash(&mut h);
        h.finish()
    }

    pub fn is_file(&self) -> bool {
        self.metadata
            .as_ref()
            .map(|x| x.is_file())
            .unwrap_or_default()
    }

    pub fn is_dir(&self) -> bool {
        self.metadata
            .as_ref()
            .map(|x| x.is_dir())
            .unwrap_or_default()
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn is_symlink(&self) -> bool {
        self.metadata
            .as_ref()
            .map(|x| x.is_symlink())
            .unwrap_or_default()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn metadata(&self) -> Option<&Metadata> {
        self.metadata.as_ref()
    }

    pub fn set_parent_id(&mut self, id: u64) {
        self.parent_id = Some(id);
    }

    pub fn set_level(&mut self, level: usize) {
        self.level = level;
    }

    pub fn add_sub_item(&mut self, item: &Self) {
        if self.subs.is_none() {
            self.subs = Some(vec![]);
        }

        if let Some(s) = self.subs.as_mut() {
            s.push(item.id);
        }
    }

    pub fn list(&self) -> Resources {
        self.tree(1)
    }

    pub fn tree(&self, level: usize) -> Resources {
        self.tree_with_cond(level, |_| true, |_| true)
    }

    /// filter: 过滤符合条件的条目
    /// is_traverse: 是否进一步遍历该条目
    pub fn tree_with_cond<F, T>(&self, level: usize, filter: F, is_traverse: T) -> Resources
    where
        F: Fn(&Path) -> bool,
        T: Fn(&Path) -> bool,
    {
        let (mut stk, mut res) = (VecDeque::new(), Resources::new());

        stk.push_front(self.clone());

        while let Some(mut ele) = stk.pop_back() {
            let mut is_continue = false;
            // 只遍历目录
            if ele.metadata.is_some() {
                if ele.metadata.as_ref().map(|m| m.is_dir()) == Some(false) {
                    is_continue = true;
                }
            } else if !ele.path.is_dir() {
                is_continue = true;
            }

            // 只遍历指定层级
            if ele.level + 1 > level {
                is_continue = true;
            }

            if !is_continue && is_traverse(&ele.path) {
                match ele.path.read_dir() {
                    Ok(dirs) => {
                        for entry in dirs {
                            match entry {
                                Ok(entry) => {
                                    let mut r = ResourceInfo::new_uncheck(entry.path());
                                    r.set_level(ele.level + 1);
                                    r.set_parent_id(ele.id);

                                    ele.add_sub_item(&r);
                                    stk.push_front(r);
                                }
                                Err(e) => {
                                    log::error!(
                                        "read entry of the `{}` failed, {}",
                                        ele.path.display(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("cannot iterate the `{}` due to {}", ele.path.display(), e);
                    }
                }
            }

            if filter(&ele.path) {
                res.add_res(ele);
            }
        }

        res
    }
}

impl Display for ResourceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.path.display()))
    }
}

/// index, name, type, created time, modified time, accessed time
impl TableShow for ResourceInfo {
    const COLS: usize = 6;

    fn head() -> Vec<String> {
        vec!["index", "name", "type", "created", "modified", "accessed"]
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn cols(&self) -> Vec<(String, Vec<String>)> {
        let mut contents = vec![vec![format!("0")], vec![format!("{}", self.path.display())]];

        if let Some(m) = self.metadata.as_ref() {
            contents.push(vec![if m.is_dir() {
                "dir"
            } else if m.is_file() {
                "file"
            } else if m.is_symlink() {
                "symlink"
            } else {
                ""
            }
            .to_string()]);

            macro_rules! metadata_time {
                ($CONTENT: ident, $M: expr) => {
                    match $M {
                        Ok(t) => {
                            $CONTENT.push(vec![format!(
                                "{}",
                                DateTime::<Utc>::from(t).format("%Y/%m/%d-%H:%M:%S")
                            )]);
                        }
                        Err(e) => {
                            log::error!("{}", e);
                            $CONTENT.push(vec![String::default()])
                        }
                    }
                };
            }

            metadata_time!(contents, m.created());
            metadata_time!(contents, m.modified());
            metadata_time!(contents, m.accessed());
        } else {
            contents.push(vec![]);
            contents.push(vec![]);
            contents.push(vec![]);
            contents.push(vec![]);
        }

        Self::head().into_iter().zip(contents).collect()
    }
}

pub struct ResourcesIter<'a, ResourceInfo: 'a> {
    iter: std::slice::Iter<'a, Rc<ResourceInfo>>,
}

impl<'a> Iterator for ResourcesIter<'a, ResourceInfo> {
    type Item = &'a ResourceInfo;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|r| r.as_ref())
    }
}

impl Resources {
    pub fn new() -> Self {
        Self {
            res_map: HashMap::new(),
            res: Vec::new(),
        }
    }

    pub fn add_res(&mut self, res: ResourceInfo) {
        let res = Rc::new(res);
        self.add_res_rec(res);
    }

    fn add_res_rec(&mut self, res: Rc<ResourceInfo>) {
        self.res_map.entry(res.id).or_default().push(res.clone());
        self.res.push(res);
    }

    pub fn iter(&self) -> ResourcesIter<'_, ResourceInfo> {
        ResourcesIter {
            iter: self.res.iter(),
        }
    }

    pub fn filter<F>(&self, filter: F) -> Self
    where
        F: Fn(&ResourceInfo) -> bool,
    {
        let mut res = Self::new();
        for info in self.res.iter() {
            if filter(info.as_ref()) {
                res.add_res_rec(info.clone())
            }
        }
        res
    }

    /// 资源个数
    pub fn nums(&self) -> usize {
        self.res.len()
    }

    pub(crate) fn res_info(&self) -> &[Rc<ResourceInfo>] {
        self.res.as_slice()
    }
}

impl From<ResourceInfo> for Resources {
    fn from(value: ResourceInfo) -> Self {
        let mut r = Self::new();
        r.add_res(value);
        r
    }
}

impl From<&ResourceInfo> for Resources {
    fn from(value: &ResourceInfo) -> Self {
        Self::from(value.clone())
    }
}

impl Display for Resources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn head(lvl: usize) -> String {
            let mut buf = String::new();

            for _ in 0..lvl.saturating_sub(1) {
                buf.push_str("│   ");
            }

            if lvl > 0 {
                buf.push_str("├──");
            }

            buf
        }

        let mut stk = VecDeque::new();
        if let Some(max_lvl) = self.res.iter().map(|r| r.level).max() {
            for lvl in 0..=max_lvl {
                for ele in self.res.iter().filter(|r| r.level == lvl) {
                    stk.push_front(ele.clone());
                }

                if !stk.is_empty() {
                    break;
                }
            }
        } else {
            return Ok(());
        }

        if let Some(p) = stk.back() {
            let mut tmp = p.path.to_path_buf();
            for _ in 0..=p.level {
                tmp.pop();
            }

            f.write_fmt(format_args!("{}", tmp.display()))?;
            f.write_char('\n')?;
        }

        while let Some(ele) = stk.pop_back() {
            if let Some(bname) = ele.path.file_name() {
                f.write_fmt(format_args!(
                    "{}{}\n",
                    head(ele.level),
                    bname.to_string_lossy()
                ))?;
            }

            if let Some(subs) = ele.subs.as_ref() {
                for sub_id in subs.iter().rev() {
                    if let Some(sub) = self.res_map.get(sub_id) {
                        for tmp in sub.iter().rev() {
                            stk.push_back(tmp.clone());
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl TableShow for Resources {
    const COLS: usize = ResourceInfo::COLS;

    fn head() -> Vec<String> {
        ResourceInfo::head()
    }

    fn cols(&self) -> Vec<(String, Vec<String>)> {
        let (mut index, mut name, mut ty, mut created, mut modified, mut accesed) =
            (vec![], vec![], vec![], vec![], vec![], vec![]);

        for (idx, ele) in self.res.iter().enumerate() {
            index.push(format!("{idx}"));
            name.push(format!("{}", ele.path.display()));
            if let Some(m) = ele.metadata.as_ref() {
                ty.push(
                    if m.is_dir() {
                        "dir"
                    } else if m.is_file() {
                        "file"
                    } else if m.is_symlink() {
                        "symlink"
                    } else {
                        ""
                    }
                    .to_string(),
                );

                macro_rules! metadata_time {
                    ($CONTENT: ident, $M: expr) => {
                        match $M {
                            Ok(t) => {
                                $CONTENT.push(format!(
                                    "{}",
                                    DateTime::<Utc>::from(t).format("%Y/%m/%d-%H:%M:%S")
                                ));
                            }
                            Err(e) => {
                                log::error!("{}", e);
                                $CONTENT.push(String::default())
                            }
                        }
                    };
                }

                metadata_time!(created, m.created());
                metadata_time!(modified, m.modified());
                metadata_time!(accesed, m.accessed());
            } else {
                ty.push(String::default());
                created.push(String::default());
                modified.push(String::default());
                accesed.push(String::default());
            }
        }

        vec![
            ("index".to_string(), index),
            ("name".to_string(), name),
            ("type".to_string(), ty),
            ("created".to_string(), created),
            ("modified".to_string(), modified),
            ("accessed".to_string(), accesed),
        ]
    }
}
