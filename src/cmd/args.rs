use std::ops::Deref;
use std::str::FromStr;
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    iter::Extend,
    path::{Path, PathBuf},
};

use clap::Args;
use regex::Regex;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::fs::ResourceInfo;

#[derive(Args, Clone)]
#[group(required = false, multiple = false, id = "key")]
pub struct KeyArgs {
    #[arg(long, group = "key")]
    #[arg(help = "the key file path")]
    pub kfile: Option<PathBuf>,

    #[arg(long, group = "key")]
    #[arg(help = "the key string")]
    pub kstr: Option<Key>,
}

#[derive(Args, Clone)]
#[group(required = true, multiple = false, id = "salt")]
pub struct SaltArgs {
    #[arg(long, group = "salt")]
    #[arg(help = "the salt file path")]
    pub sfile: Option<PathBuf>,

    #[arg(long, group = "salt")]
    #[arg(help = "the salt string")]
    pub sstr: Option<Salt>,
}

#[derive(Args, Clone)]
#[group(required = true, multiple = false, id = "iv")]
pub struct IVArgs {
    #[arg(long, group = "iv")]
    #[arg(help = "the initial vector path")]
    pub ivfile: Option<PathBuf>,

    #[arg(long, group = "iv")]
    #[arg(help = "the initial vector string")]
    pub ivstr: Option<IVector>,
}

#[derive(Zeroize, ZeroizeOnDrop, Debug, Clone)]
pub struct Key {
    key: Vec<u8>,
}

impl KeyArgs {
    pub fn set_key(&mut self, key: Key) {
        self.kfile = None;
        self.kstr = Some(key);
    }

    pub fn append_key(&mut self, mut key: Key) {
        self.prompt_input_password().unwrap();

        if let Some(k) = self.kstr.as_mut() {
            k.key.append(&mut key.key);
        } else {
            self.set_key(key);
        }
    }

    pub fn prompt_input_password(&mut self) -> anyhow::Result<()> {
        if self.kfile.is_none() && self.kstr.is_none() {
            let key = Key::read_from_stdio().unwrap();
            self.kstr = Some(key);
        }

        Ok(())
    }
}

impl SaltArgs {
    pub fn set_salt(&mut self, salt: Salt) {
        self.sfile = None;
        self.sstr = Some(salt);
    }

    pub fn append_salt(&mut self, mut salt: Salt) {
        if let Some(s) = self.sstr.as_mut() {
            s.key.append(&mut salt.key);
        } else {
            self.set_salt(salt);
        }
    }

    pub fn is_specified(&self) -> bool {
        self.sstr.is_some() || self.sfile.is_some()
    }
}

impl IVArgs {
    pub fn set_iv(&mut self, iv: IVector) {
        self.ivfile = None;
        self.ivstr = Some(iv);
    }

    pub fn append_iv(&mut self, mut iv: IVector) {
        if let Some(s) = self.ivstr.as_mut() {
            s.key.append(&mut iv.key);
        } else {
            self.set_iv(iv);
        }
    }

    pub fn is_specified(&self) -> bool {
        self.ivstr.is_some() || self.ivfile.is_some()
    }
}

impl Key {
    pub const fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn truncate(&mut self, len: usize) {
        self.key.truncate(len);
    }

    pub fn len(&self) -> usize {
        self.key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }

    fn read_from_stdio() -> anyhow::Result<Self> {
        let passwd1 = rpassword::prompt_password("Input password: ")?.into_bytes();
        let mut passwd2 = rpassword::prompt_password("Input again: ")?.into_bytes();

        anyhow::ensure!(passwd1 == passwd2, "password not same between two inputs");
        anyhow::ensure!(!passwd1.is_empty(), "password can not empty");
        passwd2.zeroize();
        Ok(Key { key: passwd1 })
    }
}

pub type Salt = Key;
pub type IVector = Key;

impl From<Vec<u8>> for Key {
    fn from(value: Vec<u8>) -> Self {
        Self { key: value }
    }
}

impl From<&[u8]> for Key {
    fn from(value: &[u8]) -> Self {
        Self {
            key: value.to_vec(),
        }
    }
}

impl TryFrom<KeyArgs> for Key {
    type Error = anyhow::Error;
    fn try_from(value: KeyArgs) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl FromStr for Key {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = Vec::from(s);
        Ok(Key::new(v))
    }
}

impl Deref for Key {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.key.as_slice()
    }
}

impl TryFrom<&KeyArgs> for Key {
    type Error = anyhow::Error;

    fn try_from(value: &KeyArgs) -> Result<Self, Self::Error> {
        if let Some(f) = value.kfile.as_deref() {
            let key = std::fs::read(f)?;
            return Ok(Key { key });
        }

        if let Some(s) = value.kstr.as_ref() {
            return Ok(s.clone());
        }

        Key::read_from_stdio()
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

impl Extend<u8> for Key {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.key.extend(iter);
    }
}

impl<const N: usize> TryFrom<Key> for [u8; N] {
    type Error = anyhow::Error;

    fn try_from(value: Key) -> Result<Self, Self::Error> {
        anyhow::ensure!(
            value.len() == N,
            "cannot convert key with length {} to [u8; {}]",
            value.len(),
            N
        );
        let mut arr = [0u8; N];
        arr.iter_mut().zip(value.key.iter()).for_each(|(a, &b)| {
            *a = b;
        });
        Ok(arr)
    }
}

impl TryFrom<SaltArgs> for Salt {
    type Error = anyhow::Error;
    fn try_from(value: SaltArgs) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&SaltArgs> for Salt {
    type Error = anyhow::Error;

    fn try_from(value: &SaltArgs) -> Result<Self, Self::Error> {
        if let Some(f) = value.sfile.as_deref() {
            let key = std::fs::read(f)?;
            return Ok(Salt { key });
        }

        if let Some(s) = value.sstr.as_ref() {
            return Ok(s.clone());
        }

        anyhow::bail!("not specified the salt data");
    }
}

impl TryFrom<IVArgs> for IVector {
    type Error = anyhow::Error;
    fn try_from(value: IVArgs) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&IVArgs> for IVector {
    type Error = anyhow::Error;

    fn try_from(value: &IVArgs) -> Result<Self, Self::Error> {
        if let Some(f) = value.ivfile.as_deref() {
            let key = std::fs::read(f)?;
            return Ok(IVector { key });
        }

        if let Some(s) = value.ivstr.as_ref() {
            return Ok(s.clone());
        }

        anyhow::bail!("not specified the initial vector data");
    }
}

#[derive(Args, Clone, Default)]
pub struct IOArgs {
    #[arg(short = 'f', long = "file")]
    #[arg(help = "the input file path")]
    pub ifile: Option<PathBuf>,

    #[arg(short, long)]
    #[arg(help = "the output file path")]
    pub ofile: Option<PathBuf>,

    #[arg(short, long)]
    #[arg(
        help = r#"truncate the input file then write content to it if the output file not specified
truncate the output file then write content to it if the output file specified"#
    )]
    pub replace: bool,

    #[arg(short = 'x', long, hide = true, value_name = "REGEX")]
    #[arg(help = "exclude file or dir")]
    pub exclude: Vec<Regex>,
}

impl IOArgs {
    pub fn set_ifile(mut self, ifile: PathBuf) -> Self {
        self.ifile = Some(ifile);
        self
    }

    pub fn set_ofile(mut self, ofile: PathBuf) -> Self {
        self.ofile = Some(ofile);
        self
    }

    pub fn set_replace(mut self, replace: bool) -> Self {
        self.replace = replace;
        self
    }

    pub fn set_exclude(mut self, exclude: Vec<Regex>) -> Self {
        self.exclude = exclude;
        self
    }

    pub fn is_have_ifile(&self) -> bool {
        self.ifile.as_deref().map(|p| p.is_file()) == Some(true)
    }

    pub fn decompose(self) -> anyhow::Result<Vec<IOArgs>> {
        let (replace, exclude) = (self.replace, self.exclude);

        let is_match = |p: &Path| {
            exclude.iter().any(|r| {
                let s = p
                    .file_name()
                    .expect("cannot get the filename of path")
                    .to_str()
                    .expect("not the UTF-8 encoded filename");
                r.is_match(s)
            })
        };

        let filter = |p: &Path| p.is_file() && !is_match(p);

        let traverser = |p: &Path| p.is_dir() && !is_match(p);

        match (self.ifile, self.ofile) {
            (Some(ipath), Some(opath)) => {
                if ipath.is_file() {
                    let p = ipath.file_name().expect("cannot get the filename of path");
                    if is_match(&ipath) {
                        Ok(vec![])
                    } else {
                        let opath = if opath.is_dir() { opath.join(p) } else { opath };
                        Ok(vec![Self::default()
                            .set_ifile(ipath)
                            .set_ofile(opath)
                            .set_replace(replace)])
                    }
                } else if ipath.is_dir() {
                    let ipath = ipath.canonicalize()?;
                    if !opath.exists() || opath.is_dir() {
                        let res_info = ResourceInfo::new(ipath.clone())?.tree_with_cond(
                            usize::MAX,
                            filter,
                            traverser,
                        );
                        let mut buf = Vec::with_capacity(res_info.nums());
                        for info in res_info.iter() {
                            let ofile = opath.join(info.path().strip_prefix(&ipath)?);
                            buf.push(
                                Self::default()
                                    .set_ifile(info.path().to_path_buf())
                                    .set_ofile(ofile)
                                    .set_replace(replace),
                            );
                        }
                        Ok(buf)
                    } else {
                        anyhow::bail!("`ofile` must be directory when `ifile` is a path");
                    }
                } else {
                    anyhow::bail!("{} is not file or directory", ipath.display());
                }
            }
            (Some(ipath), None) => {
                if ipath.is_file() {
                    if is_match(&ipath) {
                        Ok(vec![])
                    } else {
                        Ok(vec![Self::default()
                            .set_ifile(ipath.clone())
                            .set_replace(replace)])
                    }
                } else if ipath.is_dir() {
                    let res_info = ResourceInfo::new(ipath.clone())?.tree_with_cond(
                        usize::MAX,
                        filter,
                        traverser,
                    );
                    Ok(res_info
                        .iter()
                        .map(|x| {
                            Self::default()
                                .set_ifile(x.path().to_path_buf())
                                .set_replace(replace)
                        })
                        .collect())
                } else {
                    anyhow::bail!("`ifile` is not a file or a path");
                }
            }
            (None, Some(opath)) => {
                if opath.is_dir() {
                    anyhow::bail!("`ofile` need to be a file when `ifile` is `None`");
                }
                Ok(vec![Self::default().set_ofile(opath).set_replace(replace)])
            }
            (None, None) => Ok(vec![]),
        }
    }

    pub fn reader(&self, buf_size: usize) -> anyhow::Result<Option<BufReader<File>>> {
        match self.ifile.as_ref() {
            Some(f) => Ok(Some(BufReader::with_capacity(buf_size, File::open(f)?))),
            None => Ok(None),
        }
    }

    pub fn read_all_data(&self) -> anyhow::Result<Option<Vec<u8>>> {
        match self.ifile.as_ref() {
            Some(f) => Ok(Some(std::fs::read(f)?)),
            None => Ok(None),
        }
    }

    pub fn file_path(&self) -> Option<&Path> {
        if self.ofile.is_none() && self.replace {
            self.ifile.as_deref()
        } else {
            self.ofile.as_deref()
        }
    }

    pub fn writer(&self, buf_size: usize) -> anyhow::Result<Option<Box<dyn Write>>> {
        let oname = self.file_path();

        let ostream: Option<Box<dyn Write>> = match oname {
            Some(x) => {
                let Some(dirname) = x.parent() else {
                    anyhow::bail!("cannot get dirname for `{}`", x.display());
                };

                if !dirname.exists() {
                    std::fs::create_dir_all(dirname)?;
                }

                Some(Box::new(BufWriter::with_capacity(
                    buf_size,
                    OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .create_new(!(self.replace && x.is_file()))
                        .open(x)?,
                )))
            }
            None => None,
        };

        Ok(ostream)
    }

    /// the default writer is stdout
    pub fn writer_with_default(&self, buf_size: usize) -> anyhow::Result<Box<dyn Write>> {
        self.writer(buf_size)
            .map(|x| x.unwrap_or_else(|| Box::new(BufWriter::new(std::io::stdout().lock()))))
    }
}
