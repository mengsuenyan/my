use std::{fs::OpenOptions, io::Write, path::PathBuf};

use clap::{Args, Command, Subcommand};

use self::{
    argon::Argon2Args, pbkdf::PBKDFArgs, plain::PlainArgs, rsa::RSAArgs, scrypt::ScryptArgs,
};

use super::args::{Key, Salt};

pub mod argon;
pub mod pbkdf;
pub mod plain;
pub mod rsa;
pub mod scrypt;

#[derive(Args, Clone)]
#[command(about = "generate key")]
pub struct KDFArgs {
    #[command(subcommand)]
    kdf: KDFSubArgs,
}

#[derive(Subcommand, Clone)]
pub enum KDFSubArgs {
    #[command(name = "plain")]
    Plain(PlainArgs),
    #[command(name = "pbkdf1", about = "PBKDF1")]
    PBKDF1(PBKDFArgs),
    #[command(name = "pbkdf2", about = "PBKDF2")]
    PBKDF2(PBKDFArgs),
    #[command(name = "scrypt", about = "Scrypt")]
    Scrypt(ScryptArgs),
    #[command(name = "argon2", about = "Argon2")]
    Argon2(Argon2Args),
    #[command(name = "rsa")]
    RSA(RSAArgs),
}

#[derive(Args, Clone)]
pub struct KDFCommonArgs {
    #[arg(
        long,
        help = "file to save derived key content, it will output to stdout if not specified"
    )]
    ofile: Option<PathBuf>,

    #[arg(long, help = "the key byte size")]
    ksize: usize,

    #[arg(long, help = "force write if the oflile already exists")]
    force: bool,

    #[arg(long = "0x", help = "display hex format with prefix 0x")]
    prefix: bool,
}

impl KDFCommonArgs {
    fn write_with_prefix<T: Write>(mut out: T, key: &Key, prefix: bool) -> anyhow::Result<()> {
        if prefix {
            out.write_all(b"0x")?;
            for &d in key.as_ref() {
                out.write_fmt(format_args!("{:02x}", d))?;
            }
        } else {
            out.write_all(key.as_ref())?;
        }
        out.flush()?;
        Ok(())
    }

    pub fn exe(self, key: &Key) {
        assert_eq!(
            key.as_ref().len(),
            self.ksize,
            "invalid key size {}",
            key.as_ref().len()
        );

        if let Some(f) = self.ofile {
            let file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create_new(!(self.force && f.is_file()))
                .open(f)
                .unwrap();
            Self::write_with_prefix(file, key, self.prefix).unwrap();
        } else {
            let out = std::io::stdout().lock();
            Self::write_with_prefix(out, key, self.prefix).unwrap();
        }
    }

    pub(super) fn set_ksize(&mut self, ksize: usize) {
        self.ksize = ksize;
    }
}

impl KDFSubArgs {
    pub fn run(&self) -> anyhow::Result<Key> {
        match self {
            KDFSubArgs::Plain(a) => a.clone().run(),
            KDFSubArgs::PBKDF1(a) => a.pbkdf1_run(),
            KDFSubArgs::PBKDF2(a) => a.pbkdf2_run(),
            KDFSubArgs::Scrypt(a) => a.run(),
            KDFSubArgs::Argon2(a) => a.run(),
            KDFSubArgs::RSA(a) => a.run(),
        }
    }

    pub fn exe(self, _pipe: Option<&[u8]>) {
        match self {
            KDFSubArgs::Plain(p) => p.exe(),
            KDFSubArgs::PBKDF1(a) => a.pbkdf1_exe(),
            KDFSubArgs::PBKDF2(a) => a.pbkdf2_exe(),
            KDFSubArgs::Scrypt(s) => s.exe(),
            KDFSubArgs::Argon2(a) => a.exe(),
            KDFSubArgs::RSA(r) => r.exe(),
        }
    }

    pub fn set_ksize(&mut self, ksize: usize) {
        match self {
            KDFSubArgs::Plain(a) => a.set_ksize(ksize),
            KDFSubArgs::PBKDF1(a) => a.set_ksize(ksize),
            KDFSubArgs::PBKDF2(a) => a.set_ksize(ksize),
            KDFSubArgs::Scrypt(a) => a.set_ksize(ksize),
            KDFSubArgs::Argon2(a) => a.set_ksize(ksize),
            KDFSubArgs::RSA(a) => a.set_ksize(ksize),
        }
    }

    pub fn set_key(&mut self, key: Key) -> anyhow::Result<()> {
        match self {
            KDFSubArgs::Plain(a) => a.set_key(key),
            KDFSubArgs::PBKDF1(a) => a.set_key(key),
            KDFSubArgs::PBKDF2(a) => a.set_key(key),
            KDFSubArgs::Scrypt(a) => a.set_key(key),
            KDFSubArgs::Argon2(a) => a.set_key(key),
            KDFSubArgs::RSA(_) => anyhow::bail!("cannot set key when use the RSA as KDF"),
        }

        Ok(())
    }

    pub fn append_key(&mut self, key: Key) -> anyhow::Result<()> {
        match self {
            KDFSubArgs::Plain(a) => a.append_key(key),
            KDFSubArgs::PBKDF1(a) => a.append_key(key),
            KDFSubArgs::PBKDF2(a) => a.append_key(key),
            KDFSubArgs::Scrypt(a) => a.append_key(key),
            KDFSubArgs::Argon2(a) => a.append_key(key),
            KDFSubArgs::RSA(_) => anyhow::bail!("cannot append key when use the RSA as KDF"),
        }

        Ok(())
    }

    pub fn prompt_input_password(&mut self) -> anyhow::Result<()> {
        match self {
            KDFSubArgs::Plain(a) => a.key.prompt_input_password(),
            KDFSubArgs::PBKDF1(a) => a.key.prompt_input_password(),
            KDFSubArgs::PBKDF2(a) => a.key.prompt_input_password(),
            KDFSubArgs::Scrypt(a) => a.key.prompt_input_password(),
            KDFSubArgs::Argon2(a) => a.key.prompt_input_password(),
            KDFSubArgs::RSA(_) => anyhow::bail!("the RSA key must use `--kfile` or `--kstr`"),
        }
    }

    pub fn set_salt(&mut self, salt: Salt) -> anyhow::Result<()> {
        match self {
            KDFSubArgs::Plain(a) => a.set_salt(salt),
            KDFSubArgs::PBKDF1(a) => a.set_salt(salt),
            KDFSubArgs::PBKDF2(a) => a.set_salt(salt),
            KDFSubArgs::Scrypt(a) => a.set_salt(salt),
            KDFSubArgs::Argon2(a) => a.set_salt(salt),
            KDFSubArgs::RSA(_) => anyhow::bail!("cannot set salt when use the RSA as KDF"),
        }
        Ok(())
    }

    pub fn append_salt(&mut self, salt: Salt) -> anyhow::Result<()> {
        match self {
            KDFSubArgs::Plain(a) => a.append_salt(salt),
            KDFSubArgs::PBKDF1(a) => a.append_salt(salt),
            KDFSubArgs::PBKDF2(a) => a.append_salt(salt),
            KDFSubArgs::Scrypt(a) => a.append_salt(salt),
            KDFSubArgs::Argon2(a) => a.append_salt(salt),
            KDFSubArgs::RSA(_) => anyhow::bail!("cannot append salt when use the RSA as KDF"),
        }

        Ok(())
    }

    // required不起作用, 设置default_value, 上层接需重新设置ksize字段
    pub(super) fn for_crypto_args(mut c: Command) -> Command {
        let subnames = c
            .get_subcommands()
            .map(|c| {
                (
                    c.get_name().to_string(),
                    c.get_arguments().any(|a| a.get_id() == "ksize"),
                )
            })
            .collect::<Vec<_>>();

        for (name, is_have_ksize) in subnames {
            c = if is_have_ksize {
                c.mut_subcommand(name, |c| {
                    c.mut_arg("ksize", |a| {
                        // required不起作用, 设置default_value, 上层接需重新设置ksize字段
                        a.required(false)
                            .hide(true)
                            .default_value("0")
                            .help("this parameter is not work when use in the crypto command")
                    })
                    .mut_arg("ofile", |a| a.hide(true))
                    .mut_arg("force", |a| a.hide(true))
                    .mut_arg("prefix", |a| a.hide(true))
                })
            } else {
                c.mut_subcommand(name, |c| c.hide(true))
            };
        }

        c
    }
}

impl KDFArgs {
    pub fn exe(self, pipe: Option<&[u8]>) {
        self.kdf.exe(pipe)
    }
}
