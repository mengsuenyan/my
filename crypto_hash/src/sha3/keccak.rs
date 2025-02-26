use crate::keccak::sha3new::StateArray;
use crate::{Digest, Output};
use std::io::Write;

/// FIPS-202 Chapter 4, Chapter 5 <br>
///
/// `Keccak[c](N,d) = Sponge[Keccak-p[1600,24], pad10*1, 1600-c](N,d)` <br>
/// - b: 1600;
/// - rounds: 24;
/// - d: 输出hash值的位长度;
#[derive(Clone)]
pub struct SHA3<const RATE: usize, const OUTPUT_LEN: usize> {
    out: StateArray,
    buf: Vec<u8>,
    is_finalize: bool,
}

impl<const R: usize, const O: usize> SHA3<R, O> {
    // Keccak处理字串字节长度
    // const B: usize = 200;
    // B * 8 / 25
    // const W: usize = 64;
    // log2(W)
    // const L: usize = 6;
    const ROUNDS: usize = 24;

    pub fn new() -> Self {
        Self {
            out: StateArray::default(),
            buf: Vec::with_capacity(R),
            is_finalize: false,
        }
    }

    // FIPS 202 消息M后面需要补`01`, 在这里一起处理了
    //位表示: s || 1 || 0^j || 1
    fn pad_fips202_hash(&mut self) {
        let s = &mut self.buf;
        let r = s.len() % R;
        if r == R - 1 {
            // 01100001
            s.push(0x86);
        } else {
            s.push(0x06);
            s.resize(R - 1, 0);
            s.push(0x80);
        }
    }

    // 在消息后补`1111`
    pub(crate) fn pad_fips202_xof(&mut self) {
        let s = &mut self.buf;
        let r = s.len() % R;
        if r == R - 1 {
            // 11111001
            s.push(0x9f);
        } else {
            s.push(0x1f);
            s.resize(R - 1, 0);
            s.push(0x80);
        }
    }

    // 在消息后补`00`
    pub(crate) fn pad_sp800_cshake(&mut self) {
        let r = self.buf.len() % R;
        if r == R - 1 {
            // 00100001
            self.buf.push(0x84);
        } else {
            self.buf.push(0x04);
            self.buf.resize(R - 1, 0);
            self.buf.push(0x80);
        }
    }

    // 在消息后补`11`
    pub(super) fn pad_fips202_rawxof(&mut self) {
        let s = &mut self.buf;
        let r = s.len() % R;
        if r == R - 1 {
            // 11100001
            s.push(0x87);
        } else {
            s.push(0x07);
            s.resize(R - 1, 0);
            s.push(0x80);
        }
    }

    fn keccak(&mut self) {
        self.out.permutation(Self::ROUNDS);
    }

    // 调用者保证p的长度是rate的整数倍
    fn sponge(&mut self, p: Option<&[u8]>) {
        match p {
            None => {
                let s = StateArray::update(self.buf.as_slice());
                self.out ^= s;
                self.keccak();
            }
            Some(p) => {
                for chunk in p.chunks_exact(R) {
                    let s = StateArray::update(chunk);
                    // S ^ (P || 0^c)
                    self.out ^= s;
                    self.keccak();
                }
            }
        }
    }

    pub(crate) fn finalize_inner(&mut self, olen: usize) -> Output<Self> {
        if self.is_finalize {
            return Output::from_vec(self.buf.iter().take(olen).copied().collect::<Vec<_>>());
        }

        let s = StateArray::update(self.buf.as_slice());
        self.out ^= s;

        self.keccak();

        self.buf.clear();
        self.out.cvt_to_str(&mut self.buf);
        self.buf.truncate(R);
        while self.buf.len() < olen {
            let l = self.buf.len();
            self.keccak();
            self.out.cvt_to_str(&mut self.buf);
            self.buf.truncate(l + R);
        }

        self.is_finalize = true;
        Output::from_vec(self.buf.iter().take(olen).copied().collect::<Vec<_>>())
    }
}

impl<const R: usize, const O: usize> Default for SHA3<R, O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const R: usize, const O: usize> Write for SHA3<R, O> {
    fn write(&mut self, mut s: &[u8]) -> std::io::Result<usize> {
        if self.is_finalize {
            self.reset();
        }

        let slen = s.len();

        if !self.buf.is_empty() {
            let l = (R - self.buf.len()).min(s.len());
            self.buf.extend_from_slice(&s[..l]);
            s = &s[l..];
        }

        if self.buf.len() == R {
            self.sponge(None);
            self.buf.clear();
        }

        let bound = s.len() - s.len() % R;
        let chunk = &s[..bound];
        if !chunk.is_empty() {
            self.sponge(Some(chunk))
        }

        if bound != s.len() {
            self.buf.extend_from_slice(&s[bound..]);
        }

        Ok(slen)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<const R: usize, const O: usize> Digest for SHA3<R, O> {
    const BLOCK_BITS: usize = R << 3;
    const WORD_BITS: usize = R << 3;
    const DIGEST_BITS: usize = O << 3;

    fn digest(msg: &[u8]) -> Output<Self> {
        let mut sha = Self::default();
        sha.write_all(msg).unwrap();
        sha.finalize()
    }

    fn finalize(&mut self) -> Output<Self> {
        self.pad_fips202_hash();
        self.finalize_inner(O)
    }

    fn reset(&mut self) {
        self.out = StateArray::default();
        self.buf.clear();
        self.is_finalize = false;
    }
}
