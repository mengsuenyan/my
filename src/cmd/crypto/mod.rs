use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use self::{
    ae::{CCMArgs, GCMArgs},
    block::BlockCryptoArgs,
    mode::{CBCArgs, CBCCSArgs, CFBArgs, CTRArgs, ECBArgs, OFBArgs},
    rsa::RSAArgs,
    zuc::ZUCArgs,
};
use super::{args::IOArgs, config::MyConfig};
use crate::cmd::crypto::header::Header;
use clap::{Args, Subcommand};

pub mod ae;
pub mod block;
pub mod header;
pub mod mode;
pub mod rsa;
pub mod zuc;

#[derive(Args)]
#[command(about = "Cipher(PIPE | STRING | file)")]
pub struct CryptoArgs {
    #[command(subcommand)]
    c: CryptoSubArgs,
}

#[derive(Args, Clone)]
#[command(mut_arg("exclude", |a| a.hide(false)))]
pub struct CryptoCommonArgs {
    #[arg(value_name = "STRING")]
    pub msg: Option<String>,

    #[command(flatten)]
    pub io: IOArgs,

    #[arg(short, long, help = "enable decrypt")]
    pub decrypt: bool,

    #[arg(
        long = "check-hash",
        help = "check content hash force to encrypt. notice: this should not used when key changed"
    )]
    check_hash: bool,
}

#[derive(Subcommand)]
pub enum CryptoSubArgs {
    Detect {
        #[arg(value_name = "PATH")]
        #[arg(help = "the input file path")]
        ifile: PathBuf,
    },
    #[command(alias = "blk")]
    Block(BlockCryptoArgs),
    ECB(ECBArgs),
    CBC(CBCArgs),
    CFB(CFBArgs),
    OFB(OFBArgs),
    CTR(CTRArgs),
    CBCCS(CBCCSArgs),
    ZUC(ZUCArgs),
    CCM(CCMArgs),
    GCM(GCMArgs),
    RSA(RSAArgs),
}

impl CryptoArgs {
    pub fn exe(self, pipe: Option<&[u8]>) {
        self.c.exe(pipe)
    }
}

impl CryptoSubArgs {
    pub fn exe(self, pipe: Option<&[u8]>) {
        match self {
            CryptoSubArgs::Detect { ifile } => {
                let f = File::open(ifile).unwrap();
                let header = Header::from_reader(f).unwrap();
                println!("{}", header);
            }
            CryptoSubArgs::Block(a) => a.exe(pipe),
            CryptoSubArgs::ECB(a) => a.exe(pipe),
            CryptoSubArgs::CBC(a) => a.exe(pipe),
            CryptoSubArgs::CFB(a) => a.exe(pipe),
            CryptoSubArgs::OFB(a) => a.exe(pipe),
            CryptoSubArgs::CTR(a) => a.exe(pipe),
            CryptoSubArgs::CBCCS(a) => a.exe(pipe),
            CryptoSubArgs::ZUC(a) => a.exe(pipe),
            CryptoSubArgs::CCM(a) => a.exe(pipe),
            CryptoSubArgs::GCM(a) => a.exe(pipe),
            CryptoSubArgs::RSA(a) => a.exe(pipe),
        }
    }
}

impl CryptoCommonArgs {
    pub fn assert_only_one_datasource(&self, pipe: Option<&[u8]>) -> anyhow::Result<()> {
        let datasource =
            pipe.is_some() as u8 + self.io.is_have_ifile() as u8 + self.msg.is_some() as u8;
        if datasource > 1 {
            anyhow::bail!("only input the one input data source of <PIPE | STRING | ifile>");
        } else {
            Ok(())
        }
    }

    pub fn exe(self, data: &[u8]) {
        let mut ostream = self
            .io
            .writer_with_default(MyConfig::config().tmp_buf_size)
            .unwrap();
        ostream.write_all(data).unwrap();
    }

    fn read_data<'a>(
        &self,
        data: &'a [u8],
        io_arg: &IOArgs,
    ) -> anyhow::Result<Option<(&'a [u8], Header)>> {
        if self.decrypt {
            let header = Header::try_from(data)?;
            Ok(Some((&data[header.size()..], header)))
        } else {
            let digest = if self.check_hash {
                if let Some(file_path) = io_arg.file_path() {
                    Header::extract_digest(file_path)
                } else {
                    None
                }
            } else {
                None
            };

            let mut header = Header::new(String::default());
            header.set_filename(io_arg.file_path());
            header.hash(data);

            if Some(header.digest()) == digest.as_deref() {
                match io_arg.ofile.as_deref() {
                    Some(x) => {
                        log::info!(
                            "the data hash equal to encrypted file hash: `{:?}`",
                            x.display()
                        );
                    }
                    None => {
                        log::info!("the data hash equal to encrypted file hash");
                    }
                }
                Ok(None)
            } else {
                Ok(Some((data, header)))
            }
        }
    }

    fn read_from_ioargs(&self, io_arg: &IOArgs) -> anyhow::Result<Option<(Vec<u8>, Header)>> {
        let Some(data) = io_arg.read_all_data()? else {
            return Ok(None);
        };

        self.read_data(&data, io_arg)
            .map(|x| x.map(|y| (y.0.to_vec(), y.1)))
    }

    fn write_data(&self, header: Header, data: &[u8], io_arg: &IOArgs) -> anyhow::Result<()> {
        let mut writer = io_arg.writer_with_default(MyConfig::config().tmp_buf_size)?;

        if self.decrypt {
            if !header.valid_hash(data) {
                if let Some(x) = io_arg.file_path() {
                    anyhow::bail!("invalid data hash `{}`", x.display());
                } else {
                    anyhow::bail!("invalid data hash");
                }
            }
            writer.write_all(data)?;
        } else {
            let v = Vec::from(header);
            let _ = writer.write(&v)?;
            writer.write_all(data)?;
        }

        match io_arg.file_path() {
            Some(ofile) => {
                log::info!(
                    "SUCCESS({}) {}",
                    if self.decrypt { "decrypt" } else { "encrypt" },
                    ofile.display()
                );
            }
            None => {
                log::info!(
                    "SUCCESS({})",
                    if self.decrypt { "decrypt" } else { "encrypt" }
                );
            }
        }

        Ok(())
    }
}
