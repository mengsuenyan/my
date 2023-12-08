use crate::sha3::SHA3;
use crate::{Digest, Output, XOF};
use std::io::Write;

macro_rules! impl_fip202_shake {
    ($NAME: ident, $NAME_WRAPPER: ident, $INNER: ty, $PAD: ident, $DOC: meta) => {
        #[$DOC]
        #[derive(Clone)]
        pub struct $NAME {
            sha: $INNER,
            olen: usize,
        }

        impl $NAME {
            /// `desired_len`输出的字节数
            pub fn new(desired_len: usize) -> Self {
                Self {
                    sha: <$INNER>::new(),
                    olen: desired_len,
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

        impl XOF for $NAME {
            const BLOCK_BITS: usize = <$INNER>::BLOCK_BITS;
            const WORD_BITS: usize = <$INNER>::WORD_BITS;

            fn desired_len(&self) -> usize {
                self.olen
            }

            fn finalize(&mut self) -> Vec<u8> {
                let l = self.desired_len();
                // self.sha.pad_fips202_xof();
                self.sha.$PAD();
                self.sha.finalize_inner(l).to_vec()
            }

            fn reset(&mut self) {
                self.sha.reset();
            }
        }

        /// `N`摘要字节数
        #[derive(Clone)]
        pub struct $NAME_WRAPPER<const N: usize> {
            sha: $NAME,
        }

        impl<const N: usize> Default for $NAME_WRAPPER<N> {
            fn default() -> Self {
                Self { sha: $NAME::new(N) }
            }
        }

        impl<const N: usize> Write for $NAME_WRAPPER<N> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.sha.write(buf)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.sha.flush()
            }
        }

        impl<const N: usize> Digest for $NAME_WRAPPER<N> {
            const BLOCK_BITS: usize = $NAME::BLOCK_BITS;

            const WORD_BITS: usize = $NAME::WORD_BITS;
            const DIGEST_BITS: usize = N << 3;
            fn digest(msg: &[u8]) -> Output<Self> {
                let mut sha = $NAME::new(N);
                sha.write_all(msg).unwrap();
                Output::from_vec(sha.finalize())
            }
            fn finalize(&mut self) -> Output<Self> {
                Output::from_vec(self.sha.finalize().to_vec())
            }

            fn reset(&mut self) {
                self.sha.reset()
            }
        }
    };
}

impl_fip202_shake!(
    SHAKE128,
    SHAKE128Wrapper,
    SHA3<168, 0>,
    pad_fips202_xof,
    doc = r"`SHAKE128(M,d) = KECCAK[256](M || 1111, d)`"
);

impl_fip202_shake!(
    SHAKE256,
    SHAKE256Wrapper,
    SHA3<136, 0>,
    pad_fips202_xof,
    doc = r"`SHAKE256(M,d) = KECCAK[512](M || 1111, d)`"
);

impl_fip202_shake!(
    RawSHAKE128,
    RawSHAKE128Wrapper,
    SHA3<168, 0>,
    pad_fips202_rawxof,
    doc = r"`RawSHAKE128(M,d) = KECCAK[256](M || 11, d)`"
);

impl_fip202_shake!(
    RawSHAKE256,
    RawSHAKE256Wrapper,
    SHA3<136, 0>,
    pad_fips202_rawxof,
    doc = r"`RawSHAKE128(M,d) = KECCAK[256](M || 11, d)`"
);

#[cfg(test)]
mod tests {
    use crate::sha3::shake::{SHAKE128Wrapper, SHAKE256Wrapper};
    use crate::Digest;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn shake128() {
        let cases = [
            "ebaf5ccd6f37291d34bade1bbff539e7",
            "4e9e3870a3187c0b898817f12c0aaeb7",
            "0a7fddc22e37eaf05b744459f6129fd1",
            "f7275a1ebcf0a3d7fc46e235dc236a3d",
            "b485d77fdc221ecb320201c4cd09ee31",
            "21d93093fe84db44c4d2769ff7e4f2b5",
            "f99079a8eac6f051fac4e62b17f6bc86",
            "cac75ec753ceb7fcf9e9a9a6d84236c1",
            "d8ef0690db21f1f2975bb5a860f7c46b",
            "be8eb23c350d6efc131aab9275a0f2bc",
            "ebaf5ccd6f37291d34bade1bbff539e76c47afb293c5d53914d492e0bdc24045",
            "4e9e3870a3187c0b898817f12c0aaeb7b664894185f7955e9b2d5e44b154ead0",
            "0a7fddc22e37eaf05b744459f6129fd1c97cb501aaf497ecb6d5d9b1cfadcbf5",
            "f7275a1ebcf0a3d7fc46e235dc236a3d678ea7c47b642b8aec1d0855d6bc7e4e",
            "b485d77fdc221ecb320201c4cd09ee3146aaccb460a998c1b803ab4186ecdd43",
            "21d93093fe84db44c4d2769ff7e4f2b5dc920dcc58ff7f390cdd4642ef7049d5",
            "f99079a8eac6f051fac4e62b17f6bc86ff0ab03eec648e776cf65781fd9fe997",
            "cac75ec753ceb7fcf9e9a9a6d84236c1d39b8a013bd48e547c5a7409fc9eef3c",
            "d8ef0690db21f1f2975bb5a860f7c46b92e8383520b71d485cc37b267c247ca1",
            "be8eb23c350d6efc131aab9275a0f2bc44d83223ecc1b930f7e1e84bbab1c178",
        ]
        .into_iter()
        .map(|x| BigUint::from_str_radix(x, 16).unwrap().to_bytes_be());

        for (i, tgt) in cases.into_iter().enumerate() {
            let msg = format!("{}", (i % 10) + 1);
            let digest = if i < 10 {
                SHAKE128Wrapper::<16>::digest(msg.as_bytes()).to_vec()
            } else {
                SHAKE128Wrapper::<32>::digest(msg.as_bytes()).to_vec()
            };
            assert_eq!(tgt, digest, "case {i} failed")
        }
    }

    #[test]
    fn shake256() {
        let cases = [
            "2f169f9b4e6a1024752209cd5410ebb84959eee0ac73c29a04c23bd524c12f81",
            "a5a4f007abc4dfe1eb19f685efde94ca76f77dff7279de620dd52074b33fa1c6",
            "08946cd494a2c00b0e9321af0c225309e9d1b9d14ce8eeb4ed5182031c3f29b0",
            "1d8a904c4fff579bc28fd3a8065762b958f81089579cf2177ae7489a90f7d396",
            "172f84a65934fc29776758a22ad080b341b497b1967d89a20dbd8420f4d4507b",
            "cc2dc8d8adb6439605fa188ed5f0d8a43930b8e1eb8fc46e63dd9ab6a643910d",
            "112a104bd5901f13abbfdcd11be28abfeea892133b1861afe6cc4c999cc9c160",
            "09dfb269bed6186424d76680f5b936b858b844472cbc5e1ea59d24282e8b3e31",
            "0d869764040d76f626be277bc31072f1e85d9376223b23584817a2ba9834304f",
            "136d9fda60260db541102444f9d106652d4931737a832b2de40e0828feddc1f4",
        ]
        .into_iter()
        .map(|x| BigUint::from_str_radix(x, 16).unwrap().to_bytes_be());

        for (i, tgt) in cases.into_iter().enumerate() {
            let msg = format!("{}", (i % 10) + 1);
            let digest = SHAKE256Wrapper::<32>::digest(msg.as_bytes()).to_vec();
            assert_eq!(tgt, digest, "case {i} failed")
        }
    }
}
