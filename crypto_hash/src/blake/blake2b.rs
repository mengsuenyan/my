use crate::blake::blake2_para::Blake2bPara;
use crate::{Digest, Output, XOF};
use std::io::Write;
use utils::Block;

impl_blake2_common!(BLAKE2b, u64, Blake2bPara, u128);

impl BLAKE2b {
    // 单词字节大小
    const WORD_BYTES: usize = 8;
    const ROUND: usize = 12;
    const BLOCK_BYTES: usize = 128;

    const R1: u32 = 32;
    const R2: u32 = 24;
    const R3: u32 = 16;
    const R4: u32 = 63;

    const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
}

impl_blake2_spec!(BLAKE2b256, 256, BLAKE2b);
impl_blake2_spec!(BLAKE2b512, 512, BLAKE2b);
impl_blake2_spec!(BLAKE2b384, 384, BLAKE2b);
impl_blake2_spec!(BLAKE2b224, 224, BLAKE2b);
impl_blake2_spec!(BLAKE2b128, 128, BLAKE2b);

#[cfg(test)]
mod tests {
    use crate::blake::blake2b::{BLAKE2b, BLAKE2b256};
    use crate::{Digest, XOF};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::collections::HashMap;
    use std::io::Write;

    #[test]
    fn blake2b() {
        let cases = [
            (64u8, "", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
            (32u8, "abc","bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
            (64u8, "abc","BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923"),
            (64u8, "FnjIxGuftGLdw82c4J2ak6bOoAxhcgwqKg1NUE76W63WoGA8Irb3qUf5msIQnYCnFPls8EOUaNzgwTHowJFN7BuNnALqkbSFQIFMWuI67SLM3o9NCX2NJe54QC5Hli4TBjwFW2rX7LrReN0wumuSLA5gypD", "a445338ba8e9822b612bc3244af82abfd0100da79dcc19fa0ec8f6484b9df43daac557c9613f2e3fba036094ee7a1e98d0ec5e0b523f752388524d61b321bf2b"),
        ];

        let mut hs = HashMap::new();
        for (len, case, tgt) in cases {
            let blake = hs.entry(len).or_insert(BLAKE2b::new(len).unwrap());
            let tgt = BigUint::from_str_radix(tgt, 16).unwrap().to_bytes_be();
            blake.write_all(case.as_bytes()).unwrap();
            let digest = blake.finalize();
            assert_eq!(tgt, digest, "BLAKE2b-{}({case}) failed", len as usize * 8);
            blake.reset();
        }
    }

    #[test]
    fn blake2b_spec() {
        let cases = [
            "",
            "abc",
            "FnjIxGuftGLdw82c4J2ak6bOoAxhcgwqKg1NUE76W63WoGA8Irb3qUf5msIQnYCnFPls8EOUaNzgwTHowJFN7BuNnALqkbSFQIFMWuI67SLM3o9NCX2NJe54QC5Hli4TBjwFW2rX7LrReN0wumuSLA5gypD",
        ];

        let (mut blake2b, mut blake2b256) = (BLAKE2b::new(32).unwrap(), BLAKE2b256::new());
        for case in cases {
            blake2b.write_all(case.as_bytes()).unwrap();
            blake2b256.write_all(case.as_bytes()).unwrap();
            let (a, b) = (blake2b.finalize(), blake2b256.finalize().to_vec());
            assert_eq!(a, b, "blake2b != blake2b-256 for case: `{}`", case);
        }
    }
}
