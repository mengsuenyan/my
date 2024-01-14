use anyhow::Result;
use cipher::{mac::CMAC, MAC};
use std::{io::Write, path::PathBuf, thread::scope};

use crate::cmd::{crypto::mode, Cmd};

#[derive(Clone)]
pub struct CMACCmd;

impl Cmd for CMACCmd {
    const NAME: &'static str = "cmac";
    fn cmd() -> clap::Command {
        mode::common_command(Self::NAME)
    }
    fn run(&self, m: &clap::ArgMatches) {
        let (bc, bm) = mode::common_run(Self::NAME, m).unwrap();

        let ipaths = bm
            .get_many::<PathBuf>("file")
            .map(|x| x.cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let opaths = bm
            .get_many::<PathBuf>("output")
            .map(|x| x.cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let msg = bm.get_one::<String>("msg");

        assert_eq!(
            ipaths.len(),
            opaths.len(),
            "the file path numbers must equal to output path numbers"
        );

        let mut cmac = Vec::with_capacity(bc.len());
        for x in bc {
            cmac.push(CMAC::new(x).unwrap())
        }

        if let Some(msg) = msg {
            if let Some(mut c) = cmac.pop() {
                c.write_all(msg.as_bytes()).unwrap();
                let mac = c.mac();
                for x in mac {
                    print!("{:02x}", x);
                }
                println!();
            }
        }

        if cmac.len() < 2 {
            for (mut c, (ipath, opath)) in cmac.into_iter().zip(ipaths.into_iter().zip(opaths)) {
                let data = std::fs::read(ipath).unwrap();
                c.write_all(data.as_slice()).unwrap();
                std::fs::write(opath, data).unwrap();
            }
        } else {
            let x = scope::<'_, _, Result<()>>(move |s| {
                for (mut c, (ipath, opath)) in cmac.into_iter().zip(ipaths.into_iter().zip(opaths))
                {
                    s.spawn::<_, Result<()>>(move || {
                        let data = std::fs::read(ipath)?;
                        c.write_all(data.as_slice())?;
                        std::fs::write(opath, data)?;
                        Ok(())
                    });
                }
                Ok(())
            });

            x.unwrap();
        }
    }
}
