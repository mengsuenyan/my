use crate::cmd::hash::{common_cmd, common_run, BLAKE2bCmd, BLAKE2sCmd};
use crate::cmd::Cmd;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use crypto_hash::blake;
use num_bigint::BigUint;

macro_rules! impl_blake_cmd {
    ([$TYPE: ty, $HASH: ty, $NAME: literal]) => {
        impl Cmd for $TYPE {
            const NAME: &'static str = $NAME;

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
                    .arg(
                        Arg::new("key")
                            .long("key")
                            .short('k')
                            .value_parser(value_parser!(String))
                            .action(ArgAction::Set)
                            .required(false)
                            .help("BLAKE2 key value"),
                    )
                    .about(stringify!($HASH))
            }

            fn run(&self, m: &ArgMatches) {
                let (s, key) = (
                    m.get_one::<u64>("size").copied().unwrap() as usize,
                    m.get_one::<String>("key")
                        .map(|x| x.clone())
                        .unwrap_or_default().into_bytes(),
                );
                assert_eq!(
                    s & 7,
                    0,
                    "SHA512t digest bits size need to satisfy multiple of 8"
                );

                let h = <$HASH>::new_with_key((s >> 3) as u8, key).unwrap();
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
        impl_blake_cmd!([$TYPE1, $HASH1, $NAME1]);
        impl_blake_cmd!($([$TYPE2, $HASH2, $NAME2]),+);
    }
}

impl_blake_cmd!(
    [BLAKE2bCmd, blake::BLAKE2b, "blake2b"],
    [BLAKE2sCmd, blake::BLAKE2s, "blake2s"]
);
