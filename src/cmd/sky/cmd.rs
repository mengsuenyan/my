use crate::cmd::sky::SkyEncryptPara;
use crate::cmd::Cmd;
use crate::fs::ResourceInfo;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use regex::Regex;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;
use zeroize::Zeroize;

pub struct SkyCmd;

impl Cmd for SkyCmd {
    const NAME: &'static str = "sky";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("encrypt files")
            .arg(
                Arg::new("dir")
                    .value_name("DIR")
                    .action(ArgAction::Set)
                    .value_parser(value_parser!(PathBuf))
                    .required(true)
                    .help("to encrypt the specified files or all files in the specified dirs")
            )
            .arg(
                Arg::new("target-dir")
                    .long("target-dir")
                    .short('t')
                    .value_parser(value_parser!(PathBuf))
                    .action(ArgAction::Set)
                    .help("to specified the output directory")
            )
            .arg(
                Arg::new("decrypt")
                    .long("decrypt")
                    .short('d')
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .help("decrypt the file")
            )
            .arg(
                // 当指定了--target-dir, 且target-dir存在, 则会替换target-dir内容
                // 当未指定target-dir, 则会替换--dir内容
                Arg::new("replace")
                    .long("replace")
                    .short('r')
                    .action(ArgAction::SetTrue)
                    .help("replace the output content in place. Warning: this will replace the <DIR> content when not specified the `--target-dir`")
            )
            .arg(
                Arg::new("exclude")
                    .long("exclude")
                    .short('x')
                    .required(false)
                    .action(ArgAction::Append)
                    .help("exclude file or dir")
            )
            .arg(
                Arg::new("cpus")
                    .long("cpus")
                    .value_parser(value_parser!(usize))
                    .default_value("1")
                    .required(false)
                    .action(ArgAction::Set)
                    .help("`cpus` threads to encrypt")
            )
            .arg(
                Arg::new("hash")
                    .long("hash")
                    .default_value("sha3-256")
                    .action(ArgAction::Set)
                    .help("specified the hash function name")
            )
            .arg(
                Arg::new("cipher")
                    .long("cipher")
                    .default_value("aes256/ofb")
                    .action(ArgAction::Set)
                    .help("specified the cipher function name, format: block_cipher/cipher_name")
            )
    }

    fn run(&self, m: &ArgMatches) {
        let (is_decrypt, is_replace) = (m.get_flag("decrypt"), m.get_flag("replace"));
        let in_path = m
            .get_one::<PathBuf>("dir")
            .cloned()
            .unwrap()
            .canonicalize()
            .unwrap();
        assert!(in_path.exists(), "{} is not exist", in_path.display());
        let out_path = match m.get_one::<PathBuf>("target-dir") {
            Some(x) => x.clone(),
            None => {
                if is_replace {
                    log::info!(
                        "the parameter `--replace` is specified, this will replace the {} content",
                        in_path.display()
                    );
                    in_path.clone()
                } else {
                    panic!("Must to specify `--target-dir` or using `--replace` to replace `{}` content", in_path.display());
                }
            }
        };

        let exclude = m
            .get_many::<String>("exclude")
            .map(|x| {
                let mut tmp = x.cloned().collect::<Vec<String>>();
                tmp.sort();
                tmp.dedup();
                tmp.iter()
                    .map(|r| {
                        Regex::new(r).unwrap_or_else(|_| panic!("invalid regex string: {}", r))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let res_info = ResourceInfo::new(in_path.clone()).unwrap().tree_with_cond(
            usize::MAX,
            |p| {
                p.is_file()
                    && exclude.iter().all(|r| {
                        p.file_name()
                            .map(|x| r.is_match(x.to_string_lossy().as_ref()))
                            != Some(true)
                    })
            },
            |p| {
                if p.is_dir() {
                    exclude.iter().all(|r| {
                        p.file_name()
                            .map(|x| r.is_match(x.to_string_lossy().as_ref()))
                            != Some(true)
                    })
                } else {
                    false
                }
            },
        );

        let cpus = m.get_one::<usize>("cpus").copied().unwrap_or(1).max(1);
        let res_info = res_info
            .res_info()
            .chunks(res_info.nums() / cpus)
            .map(|x| x.iter().map(|y| y.deref().clone()).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        let (hash, cipher) = (
            m.get_one::<String>("hash")
                .expect("need to specified the hash function name"),
            m.get_one::<String>("cipher")
                .expect("need to specified the cipher name"),
        );

        let mut password =
            rpassword::prompt_password("Your password: ").expect("cannot read password");
        let mut password_assert =
            rpassword::prompt_password("input again: ").expect("cannot read password");
        if password != password_assert {
            eprintln!("password not same between inputs");
            std::process::exit(0x1);
        }
        password_assert.zeroize();

        thread::scope(|s| {
            for chunk in res_info {
                let (inpath, outpath, password) =
                    (in_path.clone(), out_path.clone(), password.as_str());
                s.spawn(move || {
                    let mut data = Vec::new();
                    let mut sky = match SkyEncryptPara::new()
                        .cipher_name(cipher.as_str())
                        .hash_name(hash.as_str())
                        .password(password)
                        .build()
                    {
                        Err(e) => {
                            log::error!("build the sky encrypt failed due to: {}", e);
                            return;
                        }
                        Ok(x) => x,
                    };

                    for p in chunk {
                        if !p.is_file() {
                            log::error!("`{}` is not a file", p.path().display());
                            continue;
                        }

                        let s_time = Instant::now();
                        log::info!("start crypt the file `{}-{}`", p.id(), p.path().display());
                        let Some(out_path) =
                            Self::output_path(p.path(), inpath.clone(), outpath.clone())
                        else {
                            continue;
                        };

                        if out_path.exists() && !is_replace {
                            log::error!(
                                "`{}` is exists but not specify the `--replace`",
                                out_path.display()
                            );
                            continue;
                        }

                        let Some(filename) = Self::read_file(p.path(), &mut data) else {
                            continue;
                        };

                        let content =
                            match sky.crypt(data.as_slice(), filename.as_bytes(), is_decrypt) {
                                Ok(c) => c,
                                Err(e) => {
                                    log::error!("`{}` crypt failed due to {e}", p.path().display());
                                    continue;
                                }
                            };

                        if Self::write_file(out_path, is_replace, content.as_slice()) {
                            log::info!(
                                "end crypt the file `{}` took {:?}",
                                p.id(),
                                s_time.elapsed()
                            )
                        }
                    }
                });
            }
        });

        password.zeroize();
    }
}

impl SkyCmd {
    fn read_file(p: &Path, data: &mut Vec<u8>) -> Option<String> {
        data.clear();
        match File::open(p) {
            Ok(mut f) => {
                if let Err(e) = f.read_to_end(data) {
                    log::error!("read the file `{}` failed due to: {}", p.display(), e);
                    return None;
                }
            }
            Err(e) => {
                log::error!("open the file `{}` failed due to: {}", p.display(), e);
                return None;
            }
        }

        let filename = p
            .file_name()
            .and_then(|x| x.to_str().map(|y| y.to_string()));
        if filename.is_none() {
            log::error!("`{}` is not valid UTF-8 filename", p.display());
        }
        filename
    }

    fn output_path(p: &Path, mut in_path: PathBuf, mut out_path: PathBuf) -> Option<PathBuf> {
        let tmp = if !in_path.is_file() {
            p
        } else {
            out_path.as_path()
        };
        let filename = match tmp.file_name() {
            Some(f) => f.to_os_string(),
            None => {
                log::error!("cannot get the filename of the path `{}`", p.display());
                return None;
            }
        };

        if !in_path.is_file() && in_path != out_path {
            in_path.pop();
            let suffix = match p.strip_prefix(in_path) {
                Ok(x) => x,
                Err(e) => {
                    log::error!("write the file `{}` failed due to: {}", p.display(), e);
                    return None;
                }
            };

            out_path.push(suffix);
        }

        if !out_path.pop() {
            log::error!(
                "cannot pop the filename of the path `{}`",
                out_path.display()
            );
            return None;
        }

        out_path.push(filename);

        Some(out_path)
    }

    fn write_file(out_path: PathBuf, is_replace: bool, data: &[u8]) -> bool {
        let mut tmp = out_path.clone();
        if !tmp.pop() {
            log::error!("cannot pop the filename of the path `{}`", tmp.display());
            return false;
        }

        if !tmp.as_os_str().is_empty() && !tmp.exists() {
            if let Err(e) = create_dir_all(tmp.as_path()) {
                log::error!("cannot create the dir `{}` due to: {}", tmp.display(), e);
                return false;
            }
        }

        match OpenOptions::new()
            .write(true)
            .truncate(true)
            .create_new(!is_replace || !out_path.exists())
            .open(out_path.as_path())
        {
            Ok(mut f) => match f.write_all(data) {
                Ok(_) => true,
                Err(e) => {
                    log::error!(
                        "write data to `{}` failed due to: {}",
                        out_path.display(),
                        e
                    );
                    false
                }
            },
            Err(e) => {
                log::error!(
                    "cannot open the `{}` failed due to: {}",
                    out_path.display(),
                    e
                );
                false
            }
        }
    }
}
