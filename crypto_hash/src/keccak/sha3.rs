//! # SHA-3 Standard: Permutaion-Based Hash and Extendable-Output Functions
//!
//! - [FIPS 202 SHA-3](https://csrc.nist.gov/pubs/fips/202/final)
//!
//! 实现FIPS 202 SHA-3中的KECCAK算法.
//!

use crate::HashError;
use std::ops::{BitXorAssign, Deref, DerefMut};

/// - keccak-p[b,nr]: b定义置换宽度, nr定义置换轮数; <br>
///   - 输入: 位宽度为b的字串, 置换轮数;
///   - 输出: 位宽度为b的置换后字串;
/// keccak-f[b] = keccak-p[b,24]; <br>
///   - 特化的keccak-p[b,nr], `nr = 12 + 2*l`;
/// keccak[c] = keccak-f[1600]; <br>
///   - `Sponge[keccak-p[1600,24], pad10*1, 1600 - c]`, `c=1600-r`. `r`是位率, 即字串N的分组大小;
///   - `keccak[c](N,d) = Sponge[keccak-p[1600,24], pad10*1, 1600 - c](N, d)`, d是输出字串的位长度;
///
/// FIPS 202中定义的b的可选参数如下, `w=b/25, l = log2(w)`: <br>
///
/// |b  | 25| 50 | 100 | 200 | 400 | 800 | 1600 |
/// |---|---|----|-----|-----|-----|-----|------|
/// |w  | 1 | 2  | 4   |  8  |  16 |  32 | 64   |
/// |l  | 0 | 1  |  2  |  3  |  4  |   5 |  6   |
///
///
pub struct Keccak {
    rounds: usize,
    slen: usize,
}

impl Keccak {
    /// KEECAK-f[b]
    ///
    /// 指定每次处理的字串的位数
    pub fn new(bits: usize) -> Result<Self, HashError> {
        let l = (bits / 25).ilog2() as usize;
        Self::new_with_rounds(bits, 12 + 2 * l)
    }

    /// KEECAK-p[b,nr]
    ///
    /// 指定轮数, 通用Keccak
    pub fn new_with_rounds(bits: usize, rounds: usize) -> Result<Self, HashError> {
        if bits == 0 || (bits % 25) != 0 || bits & 7 != 0 {
            return Err(HashError::Keccak(format!(
                "Invalid bits `{}`, it should be the integer multiples of 200",
                bits
            )));
        }

        let l = (bits / 25).ilog2() as usize;
        if (12 + 2 * l) < rounds {
            return Err(HashError::Keccak(format!(
                "Invalid rounds `{}`, it should be great than {} when bit is {}",
                rounds,
                12 + 2 * l,
                bits
            )));
        }

        Ok(Self {
            rounds,
            slen: bits >> 3,
        })
    }

    /// SHA3 5.2中定义的Keccak[c]参数
    pub fn sha3() -> Self {
        Self {
            rounds: 24,
            slen: 1600,
        }
    }

    pub(crate) fn rnd<'a>(
        round_idx: usize,
        s1: &'a mut StateArray,
        s2: &'a mut StateArray,
    ) -> (&'a mut StateArray, &'a mut StateArray) {
        StepMapping::theta(s1, s2);
        StepMapping::rho(s2, s1);
        StepMapping::pi(s1, s2);
        StepMapping::chi(s2, s1);
        StepMapping::iota(round_idx, s1);

        (s1, s2)
    }

    pub(crate) fn permutation(nr: usize, s: &[u8], p: &mut Vec<u8>) {
        let (mut state, mut s2) = (StateArray::new(s), StateArray::const_default(0));
        let l = state.lane_size().ilog2() as usize;
        let (mut s1, mut s2) = (&mut state, &mut s2);
        for ir in (12 + 2 * l - nr)..(12 + 2 * l) {
            (s1, s2) = Self::rnd(ir, s1, s2);
        }

        s1.cvt_to_str(p);
    }

    pub fn permute(&self, s: &[u8], p: &mut Vec<u8>) -> Result<(), HashError> {
        if s.len() != self.slen {
            Err(HashError::Keccak(format!(
                "Invalid string byte length `{}`, it should be equal to {}",
                s.len(),
                self.slen
            )))
        } else {
            Self::permutation(self.rounds, s, p);
            Ok(())
        }
    }
}

/// FIPS-202 3.1 <br>
///
/// - plane: (x,z)平面;
/// - slice: (x,y)平面;
/// - sheet: (y,z)平面;
/// - row: x轴;
/// - column: y轴;
/// - lane: z轴;
///
/// 调用者保证字串位数需要是25的整数倍, 且不超过1600.
#[derive(Copy, Clone, Debug)]
pub(crate) struct StateArray {
    arr: [[[u8; Self::Z_SIZE]; Self::Y_SIZE]; Self::X_SIZE],
    w: usize,
}

/// FIPS-202 3.2 <br>
/// - theta: 通过y轴元素之间的异或, 压缩y轴成为`(x',z')`平面. 然后将`(x',z')`更新为`(x-1, z)^(x+1,z-1)`. `(x,y,z) ^= (x',z')`;
/// - rho: 按定义的置换函数将每条z轴上的某两个元素进行置换;
/// - pi: 按定义的置换函数将每个(x,y)平面上的, 将`\`对角线上的元素按顺时针每90°置换到置换函数给定的位置上;
/// - chi: 将每条x轴上的元素替换为`(!x \land x+1) ^ x`;
/// - iota: 按定义的函数修改(0,0)平面上的z元素;
pub(crate) struct StepMapping;

impl StateArray {
    const X_SIZE: usize = 5;
    const Y_SIZE: usize = 5;
    const Z_SIZE: usize = 64;

    // (x,y)平面大小
    const fn slice_size() -> usize {
        Self::X_SIZE * Self::Y_SIZE
    }

    // z大小
    fn lane_size(&self) -> usize {
        self.w
    }

    pub(crate) const fn const_default(w: usize) -> Self {
        Self {
            arr: [[[0u8; Self::Z_SIZE]; Self::Y_SIZE]; Self::X_SIZE],
            w,
        }
    }

    // 注意Hex字串和位字串转换的奇怪关系(小端序, 不是按书写顺序大端序);
    // H_i = H_{2*i} || H_{2*(i+1)}
    // h_i = 16 * H_{2*i} + H_{2*(i+1)}
    // h_i = b_0 + b_1 * 2 + ... b_7 * 2^7;
    // b_0 || b_1 || ... || b_7
    const fn str_at_bit(s: &[u8], bits: usize) -> u8 {
        let idx = bits >> 3;
        (s[idx] >> (bits & 7)) & 1
    }

    // 调用者保证`s.len() << 3`是25的整数倍
    fn new(s: &[u8]) -> Self {
        let (mut state, w) = (Self::const_default(0), (s.len() << 3) / Self::slice_size());
        state.update(s, w);
        state
    }

    pub(crate) fn update(&mut self, s: &[u8], w: usize) {
        let bound = s.len() << 3;
        for y in 0..Self::Y_SIZE {
            for x in 0..Self::X_SIZE {
                for z in 0..w {
                    let bits = w * (Self::X_SIZE * y + x) + z;
                    if bits < bound {
                        self[x][y][z] = Self::str_at_bit(s, bits);
                    } else {
                        self[x][y][z] = 0;
                    }
                }
            }
        }
        self.w = w;
    }

    // z
    fn lane_append_to(&self, x: usize, y: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(&self[x][y][..self.lane_size()]);
    }

    // (x,z)平面
    fn plane_append_to(&self, y: usize, out: &mut Vec<u8>) {
        (0..Self::X_SIZE).for_each(|x| self.lane_append_to(x, y, out))
    }

    //  state convert to string bits
    pub(crate) fn cvt_to_str(&self, out: &mut Vec<u8>) {
        let start_len = out.len();
        (0..Self::Y_SIZE).for_each(|y| self.plane_append_to(y, out));

        let s = &mut out.as_mut_slice()[start_len..];
        let slen = s.len() >> 3;
        for i in 0..slen {
            s[i] = s
                .iter()
                .skip(i << 3)
                .take(8)
                .enumerate()
                .fold(0, |a, (i, &b)| a | (b << i));
        }

        let start_idx = slen << 3;
        let last = s
            .iter()
            .enumerate()
            .skip(start_idx)
            .fold(0u8, |last, (i, &b)| last | (b << i));

        if start_idx < s.len() {
            s[slen] = last;
            out.truncate(start_len + slen + 1);
        } else {
            out.truncate(start_len + slen);
        }
    }
}

impl BitXorAssign<&Self> for StateArray {
    fn bitxor_assign(&mut self, rhs: &Self) {
        self.iter_mut().zip(rhs.iter()).for_each(|(a, b)| {
            a.iter_mut().zip(b.iter()).for_each(|(a, b)| {
                a.iter_mut().zip(b.iter()).for_each(|(a, b)| {
                    *a ^= *b;
                })
            })
        })
    }
}

impl Default for StateArray {
    fn default() -> Self {
        Self::const_default(0)
    }
}

impl Deref for StateArray {
    type Target = [[[u8; Self::Z_SIZE]; Self::Y_SIZE]; Self::X_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.arr
    }
}

impl DerefMut for StateArray {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.arr
    }
}

impl StepMapping {
    fn theta(s: &StateArray, out: &mut StateArray) {
        out.w = s.w;

        let mut c = [[0u8; StateArray::Z_SIZE]; StateArray::X_SIZE];
        for x in 0..StateArray::X_SIZE {
            for z in 0..s.lane_size() {
                c[x][z] = s[x][0][z] ^ s[x][1][z] ^ s[x][2][z] ^ s[x][3][z] ^ s[x][4][z];
            }
        }

        let mut d = [[0u8; StateArray::Z_SIZE]; StateArray::X_SIZE];
        for x in 0..StateArray::X_SIZE {
            for z in 0..s.lane_size() {
                let (x, z) = (x as isize, z as isize);
                d[x as usize][z as usize] = c[(x - 1).rem_euclid(5) as usize][z as usize]
                    ^ c[(x + 1).rem_euclid(5) as usize]
                        [(z - 1).rem_euclid(s.lane_size() as isize) as usize];
            }
        }

        for y in 0..StateArray::Y_SIZE {
            for x in 0..StateArray::X_SIZE {
                for z in 0..s.lane_size() {
                    out[x][y][z] = s[x][y][z] ^ d[x][z];
                }
            }
        }
    }

    fn rho(s: &StateArray, out: &mut StateArray) {
        out.w = s.w;
        out[0][0] = s[0][0];

        let (mut x, mut y, w) = (1, 0, s.w as isize);
        for t in 0..=23 {
            for z in 0..w {
                out[x][y][z as usize] = s[x][y][(z - (t + 1) * (t + 2) / 2).rem_euclid(w) as usize];
            }
            (x, y) = (y, (2 * x + 3 * y) % StateArray::Y_SIZE)
        }
    }

    fn pi(s: &StateArray, out: &mut StateArray) {
        out.w = s.w;
        for y in 0..StateArray::Y_SIZE {
            for x in 0..StateArray::X_SIZE {
                for z in 0..s.lane_size() {
                    out[x][y][z] = s[(x + 3 * y) % StateArray::X_SIZE][x][z];
                }
            }
        }
    }

    fn chi(s: &StateArray, out: &mut StateArray) {
        out.w = s.w;
        for y in 0..StateArray::Y_SIZE {
            for x in 0..StateArray::X_SIZE {
                for z in 0..s.lane_size() {
                    out[x][y][z] = s[x][y][z]
                        ^ ((s[(x + 1) % StateArray::X_SIZE][y][z] ^ 1)
                            & s[(x + 2) % StateArray::X_SIZE][y][z]);
                }
            }
        }
    }

    fn rc(t: usize) -> u8 {
        if t & 255 == 0 {
            1
        } else {
            let mut r = [0u8, 1, 0, 0, 0, 0, 0, 0, 0];
            for _ in 1..=(t & 255) {
                r[0] = 0;
                r[0] ^= r[8];
                r[4] ^= r[8];
                r[5] ^= r[8];
                r[6] ^= r[8];
                r.rotate_right(1);
            }
            r[0]
        }
    }

    fn iota(round_idx: usize, s: &mut StateArray) {
        let mut rc = [0u8; StateArray::Z_SIZE];
        let l = s.lane_size().ilog2();
        for j in 0..=l {
            rc[(1 << j) - 1] = Self::rc(j as usize + 7 * round_idx);
        }

        for (z, ele) in rc.into_iter().enumerate() {
            s[0][0][z] ^= ele;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::keccak::sha3::StateArray;

    #[test]
    fn str_cvt_to_state() {
        let cases = (1..=200u8)
            .filter(|&x| (x as usize * 8) % 25 == 0)
            .map(|x| (0..x).map(|y| y).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        for (i, case) in cases.into_iter().enumerate() {
            let state = StateArray::new(case.as_slice());
            let mut buf = Vec::with_capacity(case.len());
            state.cvt_to_str(&mut buf);
            assert_eq!(buf, case, "case {i} failed with length `{}`", case.len());
        }
    }
}
