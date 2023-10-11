use crate::{Digest, Output};
use std::io::Write;
use utils::Block;

/// 国标[SM3](http://www.gmbz.org.cn/main/viewfile/20180108023812835219.html)
#[derive(Clone)]
pub struct SM3 {
    digest: [u32; Self::DIGEST_WSIZE],
    buf: Vec<u8>,
    len: usize,
    is_finalize: bool,
}

impl SM3 {
    const BLOCK_SIZE: usize = Self::BLOCK_BITS >> 3;
    const WORD_SIZE: usize = Self::WORD_BITS >> 3;
    const DIGEST_WSIZE: usize = Self::DIGEST_BITS / Self::WORD_BITS;
    const IV: [u32; Self::DIGEST_WSIZE] = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d,
        0xb0fb0e4e,
    ];

    pub fn new() -> SM3 {
        Self {
            digest: Self::IV,
            buf: Vec::with_capacity(Self::BLOCK_SIZE),
            len: 0,
            is_finalize: false,
        }
    }

    #[inline]
    const fn t_j(round_idx: usize) -> u32 {
        if round_idx < 16 {
            0x79cc4519
        } else {
            0x7a879d8a
        }
    }

    #[inline]
    const fn ff_j(round_idx: usize, x: u32, y: u32, z: u32) -> u32 {
        if round_idx < 16 {
            x ^ y ^ z
        } else {
            (x & y) | (x & z) | (y & z)
        }
    }

    #[inline]
    const fn gg_j(round_idx: usize, x: u32, y: u32, z: u32) -> u32 {
        if round_idx < 16 {
            x ^ y ^ z
        } else {
            (x & y) | ((!x) & z)
        }
    }

    #[inline]
    const fn p_0(x: u32) -> u32 {
        x ^ x.rotate_left(9) ^ x.rotate_left(17)
    }

    #[inline]
    const fn p_1(x: u32) -> u32 {
        x ^ x.rotate_left(15) ^ x.rotate_left(23)
    }

    fn update<'a>(digest: &'a mut [u32; Self::DIGEST_WSIZE], data_block: &'a [u8]) -> &'a [u8] {
        let mut itr = data_block.chunks_exact(Self::BLOCK_SIZE);

        for chunk in &mut itr {
            let mut words = [0u32; 68];

            for (word, d) in words.iter_mut().zip(chunk.chunks_exact(Self::WORD_SIZE)) {
                *word = u32::from_be_bytes(Block::to_arr_uncheck(d));
            }

            for j in 16..68 {
                words[j] = Self::p_1(words[j - 16] ^ words[j - 9] ^ words[j - 3].rotate_left(15))
                    ^ words[j - 13].rotate_left(7)
                    ^ words[j - 6];
            }

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
                digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                digest[7],
            );
            for (j, (&word_j, &word_j4)) in words.iter().zip(words.iter().skip(4)).enumerate() {
                let tmp = word_j ^ word_j4;
                let s1 = a
                    .rotate_left(12)
                    .wrapping_add(e)
                    .wrapping_add(Self::t_j(j).rotate_left(j as u32))
                    .rotate_left(7);
                let s2 = s1 ^ a.rotate_left(12);
                let t1 = Self::ff_j(j, a, b, c)
                    .wrapping_add(d)
                    .wrapping_add(s2)
                    .wrapping_add(tmp);
                let t2 = Self::gg_j(j, e, f, g)
                    .wrapping_add(h)
                    .wrapping_add(s1)
                    .wrapping_add(word_j);
                d = c;
                c = b.rotate_left(9);
                b = a;
                a = t1;
                h = g;
                g = f.rotate_left(19);
                f = e;
                e = Self::p_0(t2);
            }

            digest[0] ^= a;
            digest[1] ^= b;
            digest[2] ^= c;
            digest[3] ^= d;
            digest[4] ^= e;
            digest[5] ^= f;
            digest[6] ^= g;
            digest[7] ^= h;
        }

        itr.remainder()
    }
}

impl Default for SM3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for SM3 {
    fn write(&mut self, mut data: &[u8]) -> std::io::Result<usize> {
        if self.is_finalize {
            self.reset();
        }

        let data_len = data.len();

        if !self.buf.is_empty() {
            let l = (Self::BLOCK_SIZE - self.buf.len()).min(data.len());
            self.buf.extend(&data[..l]);
            data = &data[l..];
        }

        if self.buf.len() == Self::BLOCK_SIZE {
            let _itr = Self::update(&mut self.digest, self.buf.as_slice());
            self.buf.clear();
        }

        let itr = Self::update(&mut self.digest, data);
        self.buf.extend(itr);

        self.len += data_len;
        Ok(data_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Digest for SM3 {
    const BLOCK_BITS: usize = 512;
    const WORD_BITS: usize = 32;
    const DIGEST_BITS: usize = 256;
    fn digest(msg: &[u8]) -> Output<Self> {
        let mut sm3 = Self::default();
        sm3.write_all(msg).unwrap();
        sm3.finalize()
    }

    fn finalize(&mut self) -> Output<Self> {
        if self.is_finalize {
            return Output::from_vec(
                self.digest
                    .iter()
                    .flat_map(|x| x.to_be_bytes())
                    .collect::<Vec<_>>(),
            );
        }

        let mut tmp = [0u8; Self::BLOCK_SIZE];
        tmp[0] = 0x80;
        let len = self.len;

        if len % Self::BLOCK_SIZE < 56 {
            self.write_all(&tmp[0..(56 - (len % Self::BLOCK_SIZE))])
                .unwrap();
        } else {
            self.write_all(&tmp[0..(64 + 56 - (len % Self::BLOCK_SIZE))])
                .unwrap();
        }

        let len = (len as u64) << 3;
        self.write_all(len.to_be_bytes().as_ref()).unwrap();

        let v = self
            .digest
            .iter()
            .flat_map(|x| x.to_be_bytes())
            .collect::<Vec<_>>();

        self.is_finalize = true;
        Output::from_vec(v)
    }

    fn reset(&mut self) {
        self.is_finalize = false;
        self.len = 0;
        self.buf.clear();
        self.digest = [0; Self::DIGEST_WSIZE];
    }
}

#[cfg(test)]
mod tests {
    use crate::sm3::SM3;
    use crate::Digest;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn sm3() {
        let cases = [
            (
                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                "abc",
            ),
            (
                "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
                "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            ),
        ]
        .into_iter()
        .map(|(x, msg)| (BigUint::from_str_radix(x, 16).unwrap().to_bytes_be(), msg))
        .collect::<Vec<_>>();

        for (i, (tgt, msg)) in cases.into_iter().enumerate() {
            assert_eq!(tgt, SM3::digest(msg.as_bytes()).to_vec(), "case {i} failed");
        }
    }
}
