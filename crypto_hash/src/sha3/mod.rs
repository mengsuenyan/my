//! # SHA-3系列
//!
//! ## SHA-3 Standard: Permutaion-Based Hash and Extendable-Output Functions
//!
//! - [FIPS 202 SHA-3](https://csrc.nist.gov/pubs/fips/202/final)
//!
//! ## SHA-3 Derived Function: cSHAKE, KMAC, TupleHash, ParallelHash
//!
//! - [SP 800-184: SHA-3 Derived Function](https://csrc.nist.gov/pubs/sp/800/185/final)
//!

macro_rules! impl_fips202_hash {
    ($NAME: ident, $INNER: ty, $DOC: meta) => {
        use crate::sha3::keccak::SHA3;
        use crate::{Digest, Output};
        use std::io::Write;
        use std::marker::PhantomData;

        #[$DOC]
        #[derive(Clone)]
        pub struct $NAME {
            sha: $INNER,
        }

        impl $NAME {
            pub fn new() -> Self {
                $NAME {
                    sha: <$INNER>::new(),
                }
            }
        }

        impl Default for $NAME {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<Output<$INNER>> for Output<$NAME> {
            fn from(value: Output<$INNER>) -> Self {
                Self {
                    data: value.data,
                    digest: PhantomData,
                }
            }
        }

        impl Write for $NAME {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.sha.write(buf)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.sha.flush()
            }
        }

        impl Digest for $NAME {
            const BLOCK_BITS: usize = <$INNER>::BLOCK_BITS;
            const WORD_BITS: usize = <$INNER>::WORD_BITS;
            const DIGEST_BITS: usize = <$INNER>::DIGEST_BITS;

            fn digest(msg: &[u8]) -> Output<Self> {
                <$INNER>::digest(msg).into()
            }

            fn finalize(&mut self) -> Output<Self> {
                self.sha.finalize().into()
            }

            fn reset(&mut self) {
                self.sha.reset()
            }
        }
    };
}

mod keccak;
pub use keccak::SHA3;
mod sha224;
pub use sha224::SHA224;
mod sha256;
pub use sha256::SHA256;
mod sha384;
pub use sha384::SHA384;
mod sha512;
pub use sha512::SHA512;

mod shake;
pub use shake::{
    RawSHAKE128, RawSHAKE128Wrapper, RawSHAKE256, RawSHAKE256Wrapper, SHAKE128Wrapper,
    SHAKE256Wrapper, SHAKE128, SHAKE256,
};
