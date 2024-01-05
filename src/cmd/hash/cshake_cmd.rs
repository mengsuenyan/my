use crate::cmd::hash::{
    common_cmd, common_run, CSHAKE128Cmd, CSHAKE256Cmd, KMAC128Cmd, KMAC256Cmd, KMACXof128Cmd,
    KMACXof256Cmd,
};
use crate::cmd::Cmd;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use crypto_hash::cshake;
use num_bigint::BigUint;

macro_rules! impl_cshake_cmd {
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
                    .arg(
                        Arg::new("mname")
                            .long("mname")
                            .short('m')
                            .value_parser(value_parser!(String))
                            .action(ArgAction::Set)
                            .required(false)
                            .help("CSHAKE function name or KMAC key value"),
                    )
                    .arg(
                        Arg::new("cname")
                            .long("cname")
                            .short('c')
                            .value_parser(value_parser!(String))
                            .action(ArgAction::Set)
                            .required(false)
                            .help("CSHAKE custom name"),
                    )
                .about(stringify!($HASH))
            }

            fn run(&self, m: &ArgMatches) {
                let (s, fname, cname) = (
                    m.get_one::<usize>("size").copied().unwrap(),
                    m.get_one::<String>("fname")
                        .map(|x| x.clone())
                        .unwrap_or_default(),
                    m.get_one::<String>("cname")
                        .map(|x| x.clone())
                        .unwrap_or_default(),
                );

                let h = <$HASH>::new(s >> 3, fname.as_bytes(), cname.as_bytes()).unwrap();
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
        impl_cshake_cmd!([$TYPE1, $HASH1, $NAME1]);
        impl_cshake_cmd!($([$TYPE2, $HASH2, $NAME2]),+);
    }
}

impl_cshake_cmd!(
    [CSHAKE128Cmd, cshake::CSHAKE128, "cshake128"],
    [CSHAKE256Cmd, cshake::CSHAKE256, "cshake256"],
    [KMAC128Cmd, cshake::KMAC128, "kmac128"],
    [KMAC256Cmd, cshake::KMAC256, "kmac256"],
    [KMACXof128Cmd, cshake::KMACXof128, "kmacxof128"],
    [KMACXof256Cmd, cshake::KMACXof256, "kmacxof256"]
);
