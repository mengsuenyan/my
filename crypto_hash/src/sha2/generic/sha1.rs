use crate::{
    sha2::{f_ch, f_maj, f_parity, SHA1},
    Digest,
};
use utils::Block;

macro_rules! sha1_upd_digest {
    ($a: ident, $b: ident, $c: ident, $d: ident, $e: ident, $A: ident, $B: ident, $C: ident, $D: ident, $E: ident) => {{
        let (aa, bb, cc, dd, ee) = ($A, $B, $C, $D, $E);
        $a = aa;
        $b = bb;
        $c = cc;
        $d = dd;
        $e = ee;
    };};
}

impl SHA1 {
    #[inline]
    fn f_word_extract(w: &mut [u32; Self::BLOCK_BITS / Self::WORD_BITS], s: usize) -> u32 {
        w[s & 0xf] =
            (w[(s + 13) & 0xf] ^ w[(s + 8) & 0xf] ^ w[(s + 2) & 0xf] ^ w[s & 0xf]).rotate_left(1);
        w[s & 0xf]
    }

    pub(in crate::sha2) fn update(
        digest: &mut [u32; Self::DIGEST_BITS / Self::WORD_BITS],
        blocks: &[u8],
    ) {
        for chunk in blocks.chunks_exact(SHA1::BLOCK_SIZE) {
            let mut words = [0u32; SHA1::WORD_NUMS];
            for (word, bytes) in words.iter_mut().zip(chunk.chunks_exact(4)) {
                *word = u32::from_be_bytes(Block::to_arr_uncheck(bytes));
            }

            let (mut a, mut b, mut c, mut d, mut e) =
                (digest[0], digest[1], digest[2], digest[3], digest[4]);
            let mut j = 0;
            while j < 16 {
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f_ch(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(SHA1::K[0])
                    .wrapping_add(words[j]);
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 20 {
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f_ch(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(SHA1::K[0])
                    .wrapping_add(SHA1::f_word_extract(&mut words, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 40 {
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f_parity(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(SHA1::K[1])
                    .wrapping_add(SHA1::f_word_extract(&mut words, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 60 {
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f_maj(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(SHA1::K[2])
                    .wrapping_add(SHA1::f_word_extract(&mut words, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            while j < 80 {
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f_parity(b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(SHA1::K[3])
                    .wrapping_add(SHA1::f_word_extract(&mut words, j));
                let b_p = b.rotate_left(30);
                sha1_upd_digest!(a, b, c, d, e, t, a, b_p, c, d);
                j += 1;
            }

            digest[0] = a.wrapping_add(digest[0]);
            digest[1] = b.wrapping_add(digest[1]);
            digest[2] = c.wrapping_add(digest[2]);
            digest[3] = d.wrapping_add(digest[3]);
            digest[4] = e.wrapping_add(digest[4]);
        }
    }
}
