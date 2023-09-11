use crate::sha2::{f_ch, f_maj, SHA256};

impl SHA256 {
    #[inline]
    const fn rotate_s0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline]
    const fn rotate_s1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline]
    const fn rotate_d0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline]
    const fn rotate_d1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    pub(in crate::sha2) fn update(digest: &mut [u32; Self::DIGEST_WSIZE], blocks: &[u8]) {
        for chunk in blocks.chunks_exact(SHA256::BLOCK_SIZE) {
            let mut words = [0u32; 64];
            for (word, bytes) in words.iter_mut().zip(chunk.chunks_exact(4)) {
                *word = unsafe {
                    let ptr = bytes.as_ptr() as *const [u8; 4];
                    u32::from_be_bytes(ptr.read())
                };
            }

            (SHA256::WORD_NUMS..words.len()).for_each(|j| {
                words[j] = Self::rotate_d1(words[j - 2])
                    .wrapping_add(words[j - 7])
                    .wrapping_add(Self::rotate_d0(words[j - 15]))
                    .wrapping_add(words[j - 16]);
            });

            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
                digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                digest[7],
            );

            words.into_iter().enumerate().for_each(|(j, word)| {
                let t1 = h
                    .wrapping_add(Self::rotate_s1(e))
                    .wrapping_add(f_ch(e, f, g))
                    .wrapping_add(SHA256::K[j])
                    .wrapping_add(word);
                let t2 = Self::rotate_s0(a).wrapping_add(f_maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            });

            digest[0] = a.wrapping_add(digest[0]);
            digest[1] = b.wrapping_add(digest[1]);
            digest[2] = c.wrapping_add(digest[2]);
            digest[3] = d.wrapping_add(digest[3]);
            digest[4] = e.wrapping_add(digest[4]);
            digest[5] = f.wrapping_add(digest[5]);
            digest[6] = g.wrapping_add(digest[6]);
            digest[7] = h.wrapping_add(digest[7]);
        }
    }
}
