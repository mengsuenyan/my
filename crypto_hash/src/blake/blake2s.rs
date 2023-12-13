use crate::blake::Blake2sPara;
use crate::{Digest, Output, XOF};
use std::io::Write;
use utils::Block;

impl_blake2_common!(BLAKE2s, u32, Blake2sPara, u64);

impl BLAKE2s {
    // 单词字节大小
    const WORD_BYTES: usize = 4;
    const ROUND: usize = 10;
    const BLOCK_BYTES: usize = 64;

    const R1: u32 = 16;
    const R2: u32 = 12;
    const R3: u32 = 8;
    const R4: u32 = 7;

    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
}

impl_blake2_spec!(BLAKE2s256, 256, BLAKE2s);
impl_blake2_spec!(BLAKE2s224, 224, BLAKE2s);
impl_blake2_spec!(BLAKE2s128, 128, BLAKE2s);

#[cfg(test)]
mod tests {
    use crate::blake::BLAKE2s;
    use crate::XOF;
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::collections::HashMap;
    use std::io::Write;

    #[test]
    fn blake2s() {
        let cases = [
            (32, "", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
            (32u8, "abc","508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
            (32u8, "FnjIxGuftGLdw82c4J2ak6bOoAxhcgwqKg1NUE76W63WoGA8Irb3qUf5msIQnYCnFPls8EOUaNzgwTHowJFN7BuNnALqkbSFQIFMWuI67SLM3o9NCX2NJe54QC5Hli4TBjwFW2rX7LrReN0wumuSLA5gypD", "4417ca19b963328c7d2dfa57a73dd41b0a669303aee1c8c9baa4a721f249fd77"),
        ];

        let mut hs = HashMap::new();
        for (len, case, tgt) in cases {
            let blake = hs.entry(len).or_insert(BLAKE2s::new(len).unwrap());
            let tgt = BigUint::from_str_radix(tgt, 16).unwrap().to_bytes_be();
            blake.write_all(case.as_bytes()).unwrap();
            let digest = blake.finalize();
            assert_eq!(tgt, digest, "BLAKE2s-{}({case}) failed", len as usize * 8);
            blake.reset();
        }
    }
}
