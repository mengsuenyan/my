pub mod fp;

use clap::{Args, Subcommand};

#[derive(Args)]
#[command(about = "group theory")]
pub struct GroupArgs {
    #[command(subcommand)]
    g: GroupSubArgs,
}

#[derive(Subcommand)]
pub enum GroupSubArgs {
    Fp(fp::FpArgs),
}

impl GroupArgs {
    pub fn exe(self, _: Option<&[u8]>) {
        match self.g {
            GroupSubArgs::Fp(a) => a.exe(),
        }
    }
}
