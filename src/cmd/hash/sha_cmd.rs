use crate::cmd::hash::{
    common_cmd, common_run, RawSHAKE128Cmd, RawSHAKE256Cmd, SHA2_512tCmd, SHAKE128Cmd, SHAKE256Cmd,
};
use crate::cmd::Cmd;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use crypto_hash::{sha2::SHA512tInner, sha3};
use num_bigint::BigUint;

macro_rules! impl_desired_len_hash {
    ([$TYPE: ty, $HASH: ty, $NAME: literal]) => {
        impl Cmd for $TYPE {
            const NAME: &'static str = $NAME;

            fn cmd() -> Command {
                common_cmd(Self::NAME)
                    .arg(
                        Arg::new("size")
                            .long("size")
                            .short('s')
                            .value_parser(value_parser!(usize))
                            .action(ArgAction::Set)
                            .required(true)
                            .help("digest bits length"),
                    )
                    .about(stringify!($HASH))
            }

            fn run(&self, m: &ArgMatches) {
                let s = m.get_one::<usize>("size").copied().unwrap();
                assert_eq!(
                    s & 7,
                    0,
                    "SHA512t digest bits size need to satisfy multiple of 8"
                );

                let h = <$HASH>::new(s >> 3);
                let d = common_run(h, self.pipe.as_str(), m);

                let d = BigUint::from_bytes_be(d.as_slice());
                if m.get_flag("prefix") {
                    println!("{:#02x}", d);
                } else {
                    println!("{:02x}", d);
                }
            }
        }
    };
    ([$TYPE1: ty, $HASH1: ty, $NAME1: literal], $([$TYPE2: ty, $HASH2: ty, $NAME2: literal]),+) => {
        impl_desired_len_hash!([$TYPE1, $HASH1, $NAME1]);
        impl_desired_len_hash!($([$TYPE2, $HASH2, $NAME2]),+);
    };
}

impl_desired_len_hash!(
    [SHAKE128Cmd, sha3::SHAKE128, "shake128"],
    [SHAKE256Cmd, sha3::SHAKE256, "shake256"],
    [RawSHAKE128Cmd, sha3::RawSHAKE128, "raw-shake128"],
    [RawSHAKE256Cmd, sha3::RawSHAKE256, "raw-shake256"]
);
impl Cmd for SHA2_512tCmd {
    const NAME: &'static str = "s2-512t";

    fn cmd() -> Command {
        common_cmd(Self::NAME)
            .arg(
                Arg::new("size")
                    .long("size")
                    .short('s')
                    .value_parser(value_parser!(u64).range(8..=512))
                    .action(ArgAction::Set)
                    .required(true)
                    .help("digest bits length"),
            )
            .about("sha2::SHA512t")
    }

    fn run(&self, m: &ArgMatches) {
        let s = m.get_one::<u64>("size").copied().unwrap() as usize;
        assert_eq!(
            s & 7,
            0,
            "SHA512t digest bits size need to satisfy multiple of 8"
        );

        let h = SHA512tInner::new(s >> 3).unwrap();
        let d = common_run(h, self.pipe.as_str(), m);

        let d = BigUint::from_bytes_be(d.as_slice());
        if m.get_flag("prefix") {
            println!("{:#02x}", d);
        } else {
            println!("{:02x}", d);
        }
    }
}
