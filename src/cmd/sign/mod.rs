mod rsa;

use clap::{Args, Subcommand};
pub use rsa::RsaArgs;

#[derive(Args)]
#[command(about = "signer")]
pub struct SignArgs {
    #[command(subcommand)]
    signer: SignSubArgs,
}

#[derive(Subcommand)]
pub enum SignSubArgs {
    Rsa(rsa::RsaArgs),
}

impl SignArgs {
    pub fn exe(self, pipe: Option<&[u8]>) {
        match self.signer {
            SignSubArgs::Rsa(a) => a.exe(pipe),
        }
    }
}
