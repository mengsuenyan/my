use std::{io::Write, path::PathBuf};

use clap::{Args, Command, Subcommand};
use crypto_hash::{
    blake::{
        BLAKE2b, BLAKE2b128, BLAKE2b224, BLAKE2b256, BLAKE2b384, BLAKE2b512, BLAKE2s, BLAKE2s128,
        BLAKE2s224, BLAKE2s256,
    },
    cshake::{KMACXof128, KMACXof256, CSHAKE128, CSHAKE256, KMAC128, KMAC256},
    sha2::{self, SHA1},
    sha3,
    sm3::SM3,
    Digest, DigestX,
};
use num_bigint::BigUint;

use super::args::{Key, KeyArgs};

#[derive(Args)]
#[command(name = "h")]
#[command(about = "crypto hash command, hash(PIPE | STRING | file)")]
pub struct HashCmd {
    #[command(subcommand)]
    hfn: HashSubCmd,

    #[arg(long = "0x")]
    #[arg(help = "display hex format with prefix 0x")]
    prefix: bool,
}

#[derive(Subcommand, Clone)]
pub enum HashSubCmd {
    #[command(name = "sm3", alias = "SM3", about = "SM3")]
    SM3(StandardArgs),
    #[command(name = "s1", alias = "SHA1", about = "SHA1")]
    SHA1(StandardArgs),
    #[command(name = "s2-224", alias = "SHA2-224", about = "SHA2-224")]
    SHA2_224(StandardArgs),
    #[command(name = "s2-256", alias = "SHA2-256", about = "SHA2-256")]
    SHA2_256(StandardArgs),
    #[command(name = "s2-384", alias = "SHA2-384", about = "SHA2-384")]
    SHA2_384(StandardArgs),
    #[command(name = "s2-512", alias = "SHA2-512", about = "SHA2-512")]
    SHA2_512(StandardArgs),
    #[command(name = "s2-512t224", alias = "SHA2-512T224", about = "SHA2-512T224")]
    SHA2_512T224(StandardArgs),
    #[command(name = "s2-512t256", alias = "SHA2-512T256", about = "SHA2-512T256")]
    SHA2_512T256(StandardArgs),
    #[command(name = "s2-512t", alias = "SHA2-512t", about = "SHA2-512t")]
    SHA2_512T(XofArgs),
    #[command(name = "s3-224", alias = "SHA3-224", about = "SHA3-224")]
    SHA3_224(StandardArgs),
    #[command(name = "s3-256", alias = "SHA3-256", about = "SHA3-256")]
    SHA3_256(StandardArgs),
    #[command(name = "s3-384", alias = "SHA3-384", about = "SHA3-384")]
    SHA3_384(StandardArgs),
    #[command(name = "s3-512", alias = "SHA3-512", about = "SHA3-512")]
    SHA3_512(StandardArgs),
    #[command(name = "shake128", alias = "SHAKE128", about = "SHAKE128")]
    SHAKE128(XofArgs),
    #[command(name = "shake256", alias = "SHAKE256", about = "SHAKE256")]
    SHAKE256(XofArgs),
    #[command(name = "rshake128", alias = "RawSHAKE128", about = "RawSHAKE128")]
    RawSHAKE128(XofArgs),
    #[command(name = "rshake256", alias = "RawSHAKE256", about = "RawSHAKE256")]
    RawSHAKE256(XofArgs),
    #[command(name = "cshake128", alias = "CSHAKE128", about = "CSHAKE128")]
    CSHAKE128(CShakeArgs),
    #[command(name = "cshake256", alias = "CSHAKE256", about = "CSHAKE256")]
    CSHAKE256(CShakeArgs),
    #[command(name = "kmacxof128", alias = "KMACXoF128", about = "KMACXoF128")]
    KMACXof128(KMACXofArgs),
    #[command(name = "kmacxof256", alias = "KMACXof256", about = "KMACXof256")]
    KMACXof256(KMACXofArgs),
    #[command(name = "kmac128", alias = "KMAC128", about = "KMAC128")]
    KMAC128(KMACXofArgs),
    #[command(name = "kmac256", alias = "KMAC256", about = "KMAC256")]
    KMAC256(KMACXofArgs),
    #[command(name = "bb128", alias = "BLAKE2b128", about = "BLAKE2b128")]
    BLAKE2b128(StandardArgs),
    #[command(name = "bb224", alias = "BLAKE2b224", about = "BLAKE2b224")]
    BLAKE2b224(StandardArgs),
    #[command(name = "bb256", alias = "BLAKE2b256", about = "BLAKE2b256")]
    BLAKE2b256(StandardArgs),
    #[command(name = "bb384", alias = "BLAKE2b384", about = "BLAKE2b384")]
    BLAKE2b384(StandardArgs),
    #[command(name = "bb512", alias = "BLAKE2b512", about = "BLAKE2b512")]
    BLAKE2b512(StandardArgs),
    #[command(name = "bs128", alias = "BLAKE2s128", about = "BLAKE2s128")]
    BLAKE2s128(StandardArgs),
    #[command(name = "bs224", alias = "BLAKE2s224", about = "BLAKE2s224")]
    BLAKE2s224(StandardArgs),
    #[command(name = "bs256", alias = "BLAKE2s256", about = "BLAKE2s256")]
    BLAKE2s256(StandardArgs),
    #[command(name = "blake2b", alias = "BLAKE2b", about = "BLAKE2b")]
    BLAKE2b(XofArgs),
    #[command(name = "blake2s", alias = "BLAKE2s", about = "BLAKE2s")]
    BLAKE2s(XofArgs),
}

#[derive(Args, Clone, Default)]
pub struct StandardArgs {
    #[arg(value_name = "STRING", allow_hyphen_values = true)]
    #[arg(help = "hash string")]
    str: Option<String>,

    #[arg(short = 'f', long = "file")]
    #[arg(help = "the file path")]
    file: Option<PathBuf>,
}

#[derive(Args, Clone)]
pub struct XofArgs {
    #[command(flatten)]
    std: StandardArgs,

    #[arg(short, long)]
    #[arg(help = "the extended output function digest byte size")]
    size: usize,
}

#[derive(Args, Clone)]
pub struct CShakeArgs {
    #[command(flatten)]
    xof: XofArgs,

    #[arg(long)]
    #[arg(help = "nthe algorithm function name based on the cSHAKE")]
    fname: Option<String>,

    #[arg(long)]
    #[arg(help = "custom string")]
    cstr: Option<String>,
}

#[derive(Args, Clone)]
pub struct KMACXofArgs {
    #[command(flatten)]
    xof: XofArgs,

    #[command(flatten)]
    key: KeyArgs,

    #[arg(long)]
    #[arg(help = "custom string")]
    cstr: Option<String>,
}

impl StandardArgs {
    fn run<T: DigestX, M: AsRef<[u8]>, I: Iterator<Item = M>>(
        self,
        mut h: T,
        pipe: Option<I>,
    ) -> Vec<u8> {
        let file = self.file.inspect(|f| {
            assert!(f.exists(), "{} is not exist", f.display());
            assert!(f.is_file(), "{} is not a file", f.display());
        });

        if let Some(p) = pipe {
            for d in p {
                h.write_all(d.as_ref()).unwrap();
            }
        }

        if let Some(s) = self.str {
            h.write_all(s.as_bytes()).unwrap();
        }

        if let Some(f) = file {
            let data = std::fs::read(f).unwrap();
            h.write_all(data.as_slice()).unwrap();
        }

        h.finish_x()
    }
}

impl HashSubCmd {
    pub fn run<T: AsRef<[u8]>, I: Iterator<Item = T>>(self, pipe: Option<I>) -> Vec<u8> {
        match self {
            HashSubCmd::SM3(args) => args.run(SM3::new(), pipe),
            HashSubCmd::SHA1(args) => args.run(SHA1::new(), pipe),
            HashSubCmd::SHA2_224(args) => args.run(sha2::SHA224::new(), pipe),
            HashSubCmd::SHA2_256(args) => args.run(sha2::SHA256::new(), pipe),
            HashSubCmd::SHA2_384(args) => args.run(sha2::SHA384::new(), pipe),
            HashSubCmd::SHA2_512(args) => args.run(sha2::SHA512::new(), pipe),
            HashSubCmd::SHA2_512T224(args) => args.run(sha2::SHA512T224::new(), pipe),
            HashSubCmd::SHA2_512T256(args) => args.run(sha2::SHA512T256::new(), pipe),
            HashSubCmd::SHA2_512T(args) => args
                .std
                .run(sha2::SHA512tInner::new(args.size).unwrap(), pipe),
            HashSubCmd::SHA3_224(args) => args.run(sha3::SHA224::new(), pipe),
            HashSubCmd::SHA3_256(args) => args.run(sha3::SHA256::new(), pipe),
            HashSubCmd::SHA3_384(args) => args.run(sha3::SHA384::new(), pipe),
            HashSubCmd::SHA3_512(args) => args.run(sha3::SHA512::new(), pipe),
            HashSubCmd::SHAKE128(args) => args.std.run(sha3::SHAKE128::new(args.size), pipe),
            HashSubCmd::SHAKE256(args) => args.std.run(sha3::SHAKE256::new(args.size), pipe),
            HashSubCmd::RawSHAKE128(args) => args.std.run(sha3::RawSHAKE128::new(args.size), pipe),
            HashSubCmd::RawSHAKE256(args) => args.std.run(sha3::RawSHAKE256::new(args.size), pipe),
            HashSubCmd::CSHAKE128(args) => args.xof.std.run(
                CSHAKE128::new(
                    args.xof.size,
                    args.fname.unwrap_or_default().as_bytes(),
                    args.cstr.unwrap_or_default().as_bytes(),
                )
                .unwrap(),
                pipe,
            ),
            HashSubCmd::CSHAKE256(args) => args.xof.std.run(
                CSHAKE256::new(
                    args.xof.size,
                    args.fname.unwrap_or_default().as_bytes(),
                    args.cstr.unwrap_or_default().as_bytes(),
                )
                .unwrap(),
                pipe,
            ),
            HashSubCmd::KMACXof128(args) => args.xof.std.run(
                KMACXof128::new(
                    args.xof.size,
                    Key::try_from(args.key).unwrap().as_ref(),
                    args.cstr.unwrap_or_default().as_bytes(),
                )
                .unwrap(),
                pipe,
            ),
            HashSubCmd::KMACXof256(args) => args.xof.std.run(
                KMACXof256::new(
                    args.xof.size,
                    Key::try_from(args.key).unwrap().as_ref(),
                    args.cstr.unwrap_or_default().as_bytes(),
                )
                .unwrap(),
                pipe,
            ),
            HashSubCmd::KMAC128(args) => args.xof.std.run(
                KMAC128::new(
                    args.xof.size,
                    Key::try_from(args.key).unwrap().as_ref(),
                    args.cstr.unwrap_or_default().as_bytes(),
                )
                .unwrap(),
                pipe,
            ),
            HashSubCmd::KMAC256(args) => args.xof.std.run(
                KMAC256::new(
                    args.xof.size,
                    Key::try_from(args.key).unwrap().as_ref(),
                    args.cstr.unwrap_or_default().as_bytes(),
                )
                .unwrap(),
                pipe,
            ),
            HashSubCmd::BLAKE2b128(args) => args.run(BLAKE2b128::new(), pipe),
            HashSubCmd::BLAKE2b224(args) => args.run(BLAKE2b224::new(), pipe),
            HashSubCmd::BLAKE2b256(args) => args.run(BLAKE2b256::new(), pipe),
            HashSubCmd::BLAKE2b384(args) => args.run(BLAKE2b384::new(), pipe),
            HashSubCmd::BLAKE2b512(args) => args.run(BLAKE2b512::new(), pipe),
            HashSubCmd::BLAKE2s128(args) => args.run(BLAKE2s128::new(), pipe),
            HashSubCmd::BLAKE2s224(args) => args.run(BLAKE2s224::new(), pipe),
            HashSubCmd::BLAKE2s256(args) => args.run(BLAKE2s256::new(), pipe),
            HashSubCmd::BLAKE2b(args) => args.std.run(BLAKE2b::new(args.size as u8).unwrap(), pipe),
            HashSubCmd::BLAKE2s(args) => args.std.run(BLAKE2s::new(args.size as u8).unwrap(), pipe),
        }
    }

    pub fn hasher(&self) -> anyhow::Result<Box<dyn DigestX>> {
        Ok(match self {
            HashSubCmd::SM3(_) => Box::new(SM3::new()),
            HashSubCmd::SHA1(_) => Box::new(SHA1::new()),
            HashSubCmd::SHA2_224(_) => Box::new(sha2::SHA224::new()),
            HashSubCmd::SHA2_256(_) => Box::new(sha2::SHA256::new()),
            HashSubCmd::SHA2_384(_) => Box::new(sha2::SHA384::new()),
            HashSubCmd::SHA2_512(_) => Box::new(sha2::SHA512::new()),
            HashSubCmd::SHA2_512T224(_) => Box::new(sha2::SHA512T224::new()),
            HashSubCmd::SHA2_512T256(_) => Box::new(sha2::SHA512T256::new()),
            HashSubCmd::SHA2_512T(args) => Box::new(sha2::SHA512tInner::new(args.size)?),
            HashSubCmd::SHA3_224(_) => Box::new(sha3::SHA224::new()),
            HashSubCmd::SHA3_256(_) => Box::new(sha3::SHA256::new()),
            HashSubCmd::SHA3_384(_) => Box::new(sha3::SHA384::new()),
            HashSubCmd::SHA3_512(_) => Box::new(sha3::SHA512::new()),
            HashSubCmd::SHAKE128(args) => Box::new(sha3::SHAKE128::new(args.size)),
            HashSubCmd::SHAKE256(args) => Box::new(sha3::SHAKE256::new(args.size)),
            HashSubCmd::RawSHAKE128(args) => Box::new(sha3::RawSHAKE128::new(args.size)),
            HashSubCmd::RawSHAKE256(args) => Box::new(sha3::RawSHAKE256::new(args.size)),
            HashSubCmd::CSHAKE128(args) => Box::new(CSHAKE128::new(
                args.xof.size,
                args.fname
                    .as_deref()
                    .map(|x| x.as_bytes())
                    .unwrap_or_default(),
                args.cstr
                    .as_deref()
                    .map(|x| x.as_bytes())
                    .unwrap_or_default(),
            )?),
            HashSubCmd::CSHAKE256(args) => Box::new(CSHAKE256::new(
                args.xof.size,
                args.fname
                    .as_deref()
                    .map(|x| x.as_bytes())
                    .unwrap_or_default(),
                args.cstr
                    .as_deref()
                    .map(|x| x.as_bytes())
                    .unwrap_or_default(),
            )?),
            HashSubCmd::KMACXof128(args) => Box::new(KMACXof128::new(
                args.xof.size,
                Key::try_from(&args.key).unwrap().as_ref(),
                args.cstr
                    .as_deref()
                    .map(|x| x.as_bytes())
                    .unwrap_or_default(),
            )?),
            HashSubCmd::KMACXof256(args) => Box::new(KMACXof256::new(
                args.xof.size,
                Key::try_from(&args.key).unwrap().as_ref(),
                args.cstr
                    .as_deref()
                    .map(|x| x.as_bytes())
                    .unwrap_or_default(),
            )?),
            HashSubCmd::KMAC128(args) => Box::new(KMAC128::new(
                args.xof.size,
                Key::try_from(&args.key).unwrap().as_ref(),
                args.cstr
                    .as_deref()
                    .map(|x| x.as_bytes())
                    .unwrap_or_default(),
            )?),
            HashSubCmd::KMAC256(args) => Box::new(KMAC256::new(
                args.xof.size,
                Key::try_from(&args.key).unwrap().as_ref(),
                args.cstr
                    .as_deref()
                    .map(|x| x.as_bytes())
                    .unwrap_or_default(),
            )?),
            HashSubCmd::BLAKE2b128(_) => Box::new(BLAKE2b128::new()),
            HashSubCmd::BLAKE2b224(_) => Box::new(BLAKE2b224::new()),
            HashSubCmd::BLAKE2b256(_) => Box::new(BLAKE2b256::new()),
            HashSubCmd::BLAKE2b384(_) => Box::new(BLAKE2b384::new()),
            HashSubCmd::BLAKE2b512(_) => Box::new(BLAKE2b512::new()),
            HashSubCmd::BLAKE2s128(_) => Box::new(BLAKE2s128::new()),
            HashSubCmd::BLAKE2s224(_) => Box::new(BLAKE2s224::new()),
            HashSubCmd::BLAKE2s256(_) => Box::new(BLAKE2s256::new()),
            HashSubCmd::BLAKE2b(args) => Box::new(BLAKE2b::new(u8::try_from(args.size)?)?),
            HashSubCmd::BLAKE2s(args) => Box::new(BLAKE2s::new(u8::try_from(args.size)?)?),
        })
    }

    /// digest byte size
    pub fn digest_size(&self) -> usize {
        match self {
            HashSubCmd::SM3(_) => SM3::DIGEST_BITS >> 3,
            HashSubCmd::SHA1(_) => SHA1::DIGEST_BITS >> 3,
            HashSubCmd::SHA2_224(_) => sha2::SHA224::DIGEST_BITS >> 3,
            HashSubCmd::SHA2_256(_) => sha2::SHA256::DIGEST_BITS >> 3,
            HashSubCmd::SHA2_384(_) => sha2::SHA384::DIGEST_BITS >> 3,
            HashSubCmd::SHA2_512(_) => sha2::SHA512::DIGEST_BITS >> 3,
            HashSubCmd::SHA2_512T224(_) => sha2::SHA512T224::DIGEST_BITS >> 3,
            HashSubCmd::SHA2_512T256(_) => sha2::SHA512T256::DIGEST_BITS >> 3,
            HashSubCmd::SHA2_512T(a) => a.size,
            HashSubCmd::SHA3_224(_) => sha3::SHA224::DIGEST_BITS >> 3,
            HashSubCmd::SHA3_256(_) => sha3::SHA256::DIGEST_BITS >> 3,
            HashSubCmd::SHA3_384(_) => sha3::SHA384::DIGEST_BITS >> 3,
            HashSubCmd::SHA3_512(_) => sha3::SHA512::DIGEST_BITS >> 3,
            HashSubCmd::SHAKE128(a) => a.size,
            HashSubCmd::SHAKE256(a) => a.size,
            HashSubCmd::RawSHAKE128(a) => a.size,
            HashSubCmd::RawSHAKE256(a) => a.size,
            HashSubCmd::CSHAKE128(a) => a.xof.size,
            HashSubCmd::CSHAKE256(a) => a.xof.size,
            HashSubCmd::KMACXof128(a) => a.xof.size,
            HashSubCmd::KMACXof256(a) => a.xof.size,
            HashSubCmd::KMAC128(a) => a.xof.size,
            HashSubCmd::KMAC256(a) => a.xof.size,
            HashSubCmd::BLAKE2b128(_) => BLAKE2b128::DIGEST_BITS >> 3,
            HashSubCmd::BLAKE2b224(_) => BLAKE2b128::DIGEST_BITS >> 3,
            HashSubCmd::BLAKE2b256(_) => BLAKE2b256::DIGEST_BITS >> 3,
            HashSubCmd::BLAKE2b384(_) => BLAKE2b384::DIGEST_BITS >> 3,
            HashSubCmd::BLAKE2b512(_) => BLAKE2b512::DIGEST_BITS >> 3,
            HashSubCmd::BLAKE2s128(_) => BLAKE2s128::DIGEST_BITS >> 3,
            HashSubCmd::BLAKE2s224(_) => BLAKE2s224::DIGEST_BITS >> 3,
            HashSubCmd::BLAKE2s256(_) => BLAKE2s256::DIGEST_BITS >> 3,
            HashSubCmd::BLAKE2b(a) => a.size,
            HashSubCmd::BLAKE2s(a) => a.size,
        }
    }

    pub(super) fn hide_std_args(mut c: Command) -> Command {
        let names = c
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect::<Vec<_>>();

        for name in names {
            c = c.mut_subcommand(name, |a| {
                a.mut_arg("str", |a| a.hide(true))
                    .mut_arg("file", |a| a.hide(true))
            });
        }

        c
    }
}

impl HashCmd {
    pub fn exe(self, pipe: Option<&[u8]>) {
        let is_prefix = self.prefix;

        let digest = self.run(pipe);
        if is_prefix {
            let d = BigUint::from_bytes_be(digest.as_slice());
            println!("{:#02x}", d);
        } else {
            std::io::stdout().lock().write_all(&digest).unwrap();
        }
    }

    pub fn run(self, pipe: Option<&[u8]>) -> Vec<u8> {
        let t = [pipe.unwrap_or(&[])];
        self.hfn.run(Some(t.iter()))
    }
}
