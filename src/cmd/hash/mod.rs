use crate::cmd::Cmd;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use crypto_hash::{blake, sha2, sha3, sm3::SM3, DigestX};
use num_bigint::BigUint;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

fn common_cmd(name: &str) -> Command {
    Command::new(name.to_string())
        .arg(
            Arg::new("str")
                .value_name("STRING")
                .action(ArgAction::Set)
                .value_parser(value_parser!(String))
                .required(false)
                .help("hash string"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .action(ArgAction::Set)
                .value_parser(value_parser!(PathBuf))
                .required(false)
                .help("to specified the file path"),
        )
        .arg(
            Arg::new("prefix")
                .long("prefix")
                .required(false)
                .action(ArgAction::SetTrue)
                .help("display prefix with `0x`"),
        )
}

fn common_run<T: DigestX>(mut h: T, pipe: &[u8], m: &ArgMatches) -> Vec<u8> {
    h.write_all(pipe).unwrap();

    if let Some(x) = m.get_one::<String>("str") {
        h.write_all(x.as_bytes()).unwrap();
    }

    if let Some(f) = m.get_one::<PathBuf>("file") {
        assert!(f.exists(), "{} is not exist", f.display());
        assert!(f.is_file(), "{} is not a file", f.display());
        let mut f = File::open(f).unwrap();
        let mut v = Vec::new();
        let _len = f.read_to_end(&mut v).unwrap();
        h.write_all(v.as_slice()).unwrap();
    }

    h.finish_x()
}

macro_rules! impl_hash_cmd {
    ($NAME1: ident, $($NAME2: ident),+) => {
        impl_hash_cmd!($NAME1);
        impl_hash_cmd!($($NAME2),+);
    };
    ($NAME: ident) => {
        #[derive(Default)]
        pub struct $NAME {
            pipe: Vec<u8>,
        }

        impl $NAME {
            pub fn new(pipe: &[u8]) -> Self {
                Self {
                    pipe: pipe.to_vec(),
                }
            }
        }
    };
}

impl_hash_cmd!(
    HashCmd,
    SM3Cmd,
    SHA1Cmd,
    SHA2_224Cmd,
    SHA2_256Cmd,
    SHA2_384Cmd,
    SHA2_512Cmd,
    SHA2_512t224Cmd,
    SHA2_512t256Cmd,
    SHA2_512tCmd,
    SHA3_224Cmd,
    SHA3_256Cmd,
    SHA3_384Cmd,
    SHA3_512Cmd,
    SHAKE128Cmd,
    SHAKE256Cmd,
    RawSHAKE128Cmd,
    RawSHAKE256Cmd,
    CSHAKE128Cmd,
    CSHAKE256Cmd,
    KMACXof128Cmd,
    KMACXof256Cmd,
    KMAC128Cmd,
    KMAC256Cmd,
    BLAKE2b128Cmd,
    BLAKE2b224Cmd,
    BLAKE2b256Cmd,
    BLAKE2b384Cmd,
    BLAKE2b512Cmd,
    BLAKE2s128Cmd,
    BLAKE2s224Cmd,
    BLAKE2s256Cmd,
    BLAKE2bCmd,
    BLAKE2sCmd
);

macro_rules! impl_cmd_for_hashcmd {
    ([$TYPE1: ty, $HASH1: ty, $NAME1: literal], $([$TYPE2: ty, $HASH2: ty, $NAME2: literal]),+) => {
        impl_cmd_for_hashcmd!([$TYPE1, $HASH1, $NAME1]);
        impl_cmd_for_hashcmd!($([$TYPE2, $HASH2, $NAME2]),+);
    };
    ([$TYPE: ty, $HASH: ty, $NAME: literal]) => {
        impl Cmd for $TYPE{
            const NAME: &'static str = $NAME;
            fn cmd() -> Command {
                common_cmd(Self::NAME)
                .about(stringify!($HASH))
            }

            fn run(&self, m: &ArgMatches) {
                let d = common_run(<$HASH>::new(), self.pipe.as_slice(), m);
                let d = BigUint::from_bytes_be(d.as_slice());
                if m.get_flag("prefix") {
                    println!("{:#02x}", d);
                } else {
                    println!("{:02x}", d);
                }
            }
        }
    };
}

impl_cmd_for_hashcmd!(
    [SM3Cmd, SM3, "sm3"],
    [SHA1Cmd, sha2::SHA1, "s1"],
    [SHA2_224Cmd, sha2::SHA224, "s2-224"],
    [SHA2_256Cmd, sha2::SHA256, "s2-256"],
    [SHA2_384Cmd, sha2::SHA384, "s2-384"],
    [SHA2_512Cmd, sha2::SHA512, "s2-512"],
    [SHA2_512t224Cmd, sha2::SHA512T224, "s2-t-224"],
    [SHA2_512t256Cmd, sha2::SHA512T256, "s2-t-256"],
    [SHA3_224Cmd, sha3::SHA224, "s3-224"],
    [SHA3_256Cmd, sha3::SHA256, "s3-256"],
    [SHA3_384Cmd, sha3::SHA384, "s3-384"],
    [SHA3_512Cmd, sha3::SHA512, "s3-512"],
    [BLAKE2b128Cmd, blake::BLAKE2b128, "bb128"],
    [BLAKE2b224Cmd, blake::BLAKE2b224, "bb224"],
    [BLAKE2b256Cmd, blake::BLAKE2b256, "bb256"],
    [BLAKE2b384Cmd, blake::BLAKE2b384, "bb384"],
    [BLAKE2b512Cmd, blake::BLAKE2b512, "bb512"],
    [BLAKE2s128Cmd, blake::BLAKE2s128, "bs128"],
    [BLAKE2s224Cmd, blake::BLAKE2s224, "bs224"],
    [BLAKE2s256Cmd, blake::BLAKE2s256, "bs256"]
);

mod blake_cmd;
mod cshake_cmd;
mod sha_cmd;

impl Cmd for HashCmd {
    const NAME: &'static str = "h";

    fn cmd() -> Command {
        Command::new(Self::NAME)
            .about("hash command")
            .subcommand(SM3Cmd::cmd())
            .subcommand(SHA1Cmd::cmd())
            .subcommand(SHA2_224Cmd::cmd())
            .subcommand(SHA2_256Cmd::cmd())
            .subcommand(SHA2_384Cmd::cmd())
            .subcommand(SHA2_512Cmd::cmd())
            .subcommand(SHA2_512t224Cmd::cmd())
            .subcommand(SHA2_512t256Cmd::cmd())
            .subcommand(SHA2_512tCmd::cmd())
            .subcommand(SHA2_512tCmd::cmd())
            .subcommand(SHA3_224Cmd::cmd())
            .subcommand(SHA3_256Cmd::cmd())
            .subcommand(SHA3_384Cmd::cmd())
            .subcommand(SHA3_512Cmd::cmd())
            .subcommand(SHAKE128Cmd::cmd())
            .subcommand(SHAKE256Cmd::cmd())
            .subcommand(RawSHAKE128Cmd::cmd())
            .subcommand(RawSHAKE256Cmd::cmd())
            .subcommand(CSHAKE128Cmd::cmd())
            .subcommand(CSHAKE256Cmd::cmd())
            .subcommand(KMACXof128Cmd::cmd())
            .subcommand(KMACXof256Cmd::cmd())
            .subcommand(KMAC128Cmd::cmd())
            .subcommand(KMAC256Cmd::cmd())
            .subcommand(BLAKE2b128Cmd::cmd())
            .subcommand(BLAKE2b224Cmd::cmd())
            .subcommand(BLAKE2b256Cmd::cmd())
            .subcommand(BLAKE2b384Cmd::cmd())
            .subcommand(BLAKE2b512Cmd::cmd())
            .subcommand(BLAKE2s128Cmd::cmd())
            .subcommand(BLAKE2s224Cmd::cmd())
            .subcommand(BLAKE2s256Cmd::cmd())
            .subcommand(BLAKE2bCmd::cmd())
            .subcommand(BLAKE2sCmd::cmd())
    }

    fn run(&self, m: &ArgMatches) {
        match m.subcommand() {
            Some((SM3Cmd::NAME, m)) => SM3Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA1Cmd::NAME, m)) => SHA1Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA2_224Cmd::NAME, m)) => SHA2_224Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA2_256Cmd::NAME, m)) => SHA2_256Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA2_384Cmd::NAME, m)) => SHA2_384Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA2_512Cmd::NAME, m)) => SHA2_512Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA2_512t224Cmd::NAME, m)) => SHA2_512t224Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA2_512t256Cmd::NAME, m)) => SHA2_512t256Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA2_512tCmd::NAME, m)) => SHA2_512tCmd::new(self.pipe.as_slice()).run(m),
            Some((SHA3_224Cmd::NAME, m)) => SHA3_224Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA3_256Cmd::NAME, m)) => SHA3_256Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA3_384Cmd::NAME, m)) => SHA3_384Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHA3_512Cmd::NAME, m)) => SHA3_512Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHAKE128Cmd::NAME, m)) => SHAKE128Cmd::new(self.pipe.as_slice()).run(m),
            Some((SHAKE256Cmd::NAME, m)) => SHAKE256Cmd::new(self.pipe.as_slice()).run(m),
            Some((RawSHAKE128Cmd::NAME, m)) => RawSHAKE128Cmd::new(self.pipe.as_slice()).run(m),
            Some((RawSHAKE256Cmd::NAME, m)) => RawSHAKE256Cmd::new(self.pipe.as_slice()).run(m),
            Some((CSHAKE128Cmd::NAME, m)) => CSHAKE128Cmd::new(self.pipe.as_slice()).run(m),
            Some((CSHAKE256Cmd::NAME, m)) => CSHAKE256Cmd::new(self.pipe.as_slice()).run(m),
            Some((KMACXof128Cmd::NAME, m)) => KMACXof128Cmd::new(self.pipe.as_slice()).run(m),
            Some((KMACXof256Cmd::NAME, m)) => KMACXof256Cmd::new(self.pipe.as_slice()).run(m),
            Some((KMAC128Cmd::NAME, m)) => KMAC128Cmd::new(self.pipe.as_slice()).run(m),
            Some((KMAC256Cmd::NAME, m)) => KMAC256Cmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2b128Cmd::NAME, m)) => BLAKE2b128Cmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2b224Cmd::NAME, m)) => BLAKE2b224Cmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2b256Cmd::NAME, m)) => BLAKE2b256Cmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2b384Cmd::NAME, m)) => BLAKE2b384Cmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2b512Cmd::NAME, m)) => BLAKE2b512Cmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2s128Cmd::NAME, m)) => BLAKE2s128Cmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2s224Cmd::NAME, m)) => BLAKE2s224Cmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2s256Cmd::NAME, m)) => BLAKE2s256Cmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2bCmd::NAME, m)) => BLAKE2bCmd::new(self.pipe.as_slice()).run(m),
            Some((BLAKE2sCmd::NAME, m)) => BLAKE2sCmd::new(self.pipe.as_slice()).run(m),
            Some((other, _m)) => panic!("not support the {other} hash algorithm"),
            None => panic!("need to specified the hash algorithm"),
        }
    }
}
