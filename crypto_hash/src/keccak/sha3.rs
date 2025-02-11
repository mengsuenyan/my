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
///
/// keccak-f[b] = keccak-p[b,24]; <br>
///   - 特化的keccak-p[b,nr], `nr = 12 + 2*l`;
///
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

    pub(crate) fn rnd(round_idx: usize, s: StateArray) -> StateArray {
        let s = StepMapping::theta(s);
        let s = StepMapping::rho(s);
        let s = StepMapping::pi(s);
        let s = StepMapping::chi(s);
        StepMapping::iota(round_idx, s)
    }

    pub(crate) fn permutation(nr: usize, s: &[u8], p: &mut Vec<u8>) {
        let mut state = StateArray::new(s);
        let l = state.lane_size().ilog2() as usize;
        for ir in (12 + 2 * l - nr)..(12 + 2 * l) {
            state = Self::rnd(ir, state);
        }

        state.cvt_to_str(p);
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

type StateArrayInner = [[[u8; 64]; 5]; 5];

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
    arr: StateArrayInner,
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
    #[inline]
    #[allow(unused)]
    const fn str_at_bit(s: &[u8], bits: usize) -> u8 {
        let idx = bits >> 3;
        (s[idx] >> (bits & 7)) & 1
    }

    // 调用者保证`s.len() << 3`是25的整数倍
    fn new(s: &[u8]) -> Self {
        Self::update(s, (s.len() << 3) / Self::slice_size())
    }

    // 调用者保证`s.len()`和`w`是8的整数倍
    pub(crate) fn update(s: &[u8], w: usize) -> StateArray {
        debug_assert_eq!(w & 7, 0);

        Self {
            arr: Self::cvt_to_bits(s, w),
            w,
        }
    }

    pub(crate) fn cvt_to_bits(
        s: &[u8],
        w: usize,
    ) -> [[[u8; Self::Z_SIZE]; Self::Y_SIZE]; Self::X_SIZE] {
        let mut arr = [[[0u8; Self::Z_SIZE]; Self::Y_SIZE]; Self::X_SIZE];
        let w_b = w / 8;
        arr.iter_mut().enumerate().for_each(|(x, a)| {
            a.iter_mut().enumerate().for_each(|(y, a)| {
                let (b_start, mut z) = (w_b * (Self::X_SIZE * y + x), 0);
                for &d in s.iter().skip(b_start).take(w_b) {
                    let mut d = d;
                    for _ in 0..8usize {
                        a[z] = d & 1;
                        d >>= 1;
                        z += 1;
                    }
                }
            });
        });
        arr
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

    #[inline]
    fn as_u128_arr(x: &[u8; Self::Z_SIZE]) -> &[u128; Self::Z_SIZE / 16] {
        unsafe { std::mem::transmute::<&[u8; Self::Z_SIZE], &[u128; Self::Z_SIZE / 16]>(x) }
    }

    #[inline]
    fn cvt_u128_arr(x: [u8; Self::Z_SIZE]) -> [u128; Self::Z_SIZE / 16] {
        unsafe { std::mem::transmute::<[u8; Self::Z_SIZE], [u128; Self::Z_SIZE / 16]>(x) }
    }

    #[inline]
    fn as_u128_arr_mut(x: &mut [u8; Self::Z_SIZE]) -> &mut [u128; Self::Z_SIZE / 16] {
        unsafe { std::mem::transmute::<&mut [u8; Self::Z_SIZE], &mut [u128; Self::Z_SIZE / 16]>(x) }
    }

    #[inline]
    fn cvt_u128_vec(x: StateArrayInner) -> [u128; 100] {
        unsafe { std::mem::transmute::<StateArrayInner, [u128; 100]>(x) }
    }

    #[inline]
    fn as_u128_vec_mut(x: &mut StateArrayInner) -> &mut [u128; 100] {
        unsafe { std::mem::transmute::<&mut StateArrayInner, &mut [u128; 100]>(x) }
    }
}

impl BitXorAssign<Self> for StateArray {
    fn bitxor_assign(&mut self, rhs: Self) {
        let (x, y) = (
            Self::as_u128_vec_mut(&mut self.arr),
            Self::cvt_u128_vec(rhs.arr),
        );
        x.iter_mut().zip(y).for_each(|(a, b)| *a ^= b);
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
    fn theta(mut s: StateArray) -> StateArray {
        let mut c = [[0u8; StateArray::Z_SIZE]; StateArray::X_SIZE];
        c.iter_mut().zip(s.iter()).for_each(|(a, b)| {
            let a = StateArray::as_u128_arr_mut(a);
            let (b0, b1, b2, b3, b4) = (
                StateArray::as_u128_arr(&b[0]),
                StateArray::as_u128_arr(&b[1]),
                StateArray::as_u128_arr(&b[2]),
                StateArray::as_u128_arr(&b[3]),
                StateArray::as_u128_arr(&b[4]),
            );
            a[0] = b0[0] ^ b1[0] ^ b2[0] ^ b3[0] ^ b4[0];
            a[1] = b0[1] ^ b1[1] ^ b2[1] ^ b3[1] ^ b4[1];
            a[2] = b0[2] ^ b1[2] ^ b2[2] ^ b3[2] ^ b4[2];
            a[3] = b0[3] ^ b1[3] ^ b2[3] ^ b3[3] ^ b4[3];
        });

        let mut d = [[0u8; StateArray::Z_SIZE]; StateArray::X_SIZE];
        for z in 0..s.lane_size() {
            let z_c = if z == 0 { s.lane_size() - 1 } else { z - 1 };
            d[0][z] = c[4][z] ^ c[1][z_c];
            d[1][z] = c[0][z] ^ c[2][z_c];
            d[2][z] = c[1][z] ^ c[3][z_c];
            d[3][z] = c[2][z] ^ c[4][z_c];
            d[4][z] = c[3][z] ^ c[0][z_c];
        }

        s.iter_mut().zip(d).for_each(|(a, b)| {
            let b = StateArray::cvt_u128_arr(b);
            a.iter_mut().for_each(|a| {
                let a = StateArray::as_u128_arr_mut(a);
                a.iter_mut().zip(b).for_each(|(a, b)| *a ^= b);
            });
        });

        s
    }

    #[rustfmt::skip]
    fn rho(s: StateArray) -> StateArray {
        if s.w != 64 {
            let (mut x, mut y, w, mut out) = (1, 0, s.w as isize, s);
            for t in 0..=23 {
                for z in 0..w {
                    let z2 = (z - (t + 1) * (t + 2) / 2).rem_euclid(w);
                    out.arr[x][y][z as usize] =
                        s.arr[x][y][z2 as usize];
                }
                (x, y) = (y, (2 * x + 3 * y) % StateArray::Y_SIZE)
            }
            return out;
        }
        let mut out = s;
out.arr[1][0][0]=s.arr[1][0][63];out.arr[1][0][1]=s.arr[1][0][0];out.arr[1][0][2]=s.arr[1][0][1];out.arr[1][0][3]=s.arr[1][0][2];out.arr[1][0][4]=s.arr[1][0][3];out.arr[1][0][5]=s.arr[1][0][4];out.arr[1][0][6]=s.arr[1][0][5];out.arr[1][0][7]=s.arr[1][0][6];out.arr[1][0][8]=s.arr[1][0][7];out.arr[1][0][9]=s.arr[1][0][8];
out.arr[1][0][10]=s.arr[1][0][9];out.arr[1][0][11]=s.arr[1][0][10];out.arr[1][0][12]=s.arr[1][0][11];out.arr[1][0][13]=s.arr[1][0][12];out.arr[1][0][14]=s.arr[1][0][13];out.arr[1][0][15]=s.arr[1][0][14];out.arr[1][0][16]=s.arr[1][0][15];out.arr[1][0][17]=s.arr[1][0][16];out.arr[1][0][18]=s.arr[1][0][17];out.arr[1][0][19]=s.arr[1][0][18];
out.arr[1][0][20]=s.arr[1][0][19];out.arr[1][0][21]=s.arr[1][0][20];out.arr[1][0][22]=s.arr[1][0][21];out.arr[1][0][23]=s.arr[1][0][22];out.arr[1][0][24]=s.arr[1][0][23];out.arr[1][0][25]=s.arr[1][0][24];out.arr[1][0][26]=s.arr[1][0][25];out.arr[1][0][27]=s.arr[1][0][26];out.arr[1][0][28]=s.arr[1][0][27];out.arr[1][0][29]=s.arr[1][0][28];
out.arr[1][0][30]=s.arr[1][0][29];out.arr[1][0][31]=s.arr[1][0][30];out.arr[1][0][32]=s.arr[1][0][31];out.arr[1][0][33]=s.arr[1][0][32];out.arr[1][0][34]=s.arr[1][0][33];out.arr[1][0][35]=s.arr[1][0][34];out.arr[1][0][36]=s.arr[1][0][35];out.arr[1][0][37]=s.arr[1][0][36];out.arr[1][0][38]=s.arr[1][0][37];out.arr[1][0][39]=s.arr[1][0][38];
out.arr[1][0][40]=s.arr[1][0][39];out.arr[1][0][41]=s.arr[1][0][40];out.arr[1][0][42]=s.arr[1][0][41];out.arr[1][0][43]=s.arr[1][0][42];out.arr[1][0][44]=s.arr[1][0][43];out.arr[1][0][45]=s.arr[1][0][44];out.arr[1][0][46]=s.arr[1][0][45];out.arr[1][0][47]=s.arr[1][0][46];out.arr[1][0][48]=s.arr[1][0][47];out.arr[1][0][49]=s.arr[1][0][48];
out.arr[1][0][50]=s.arr[1][0][49];out.arr[1][0][51]=s.arr[1][0][50];out.arr[1][0][52]=s.arr[1][0][51];out.arr[1][0][53]=s.arr[1][0][52];out.arr[1][0][54]=s.arr[1][0][53];out.arr[1][0][55]=s.arr[1][0][54];out.arr[1][0][56]=s.arr[1][0][55];out.arr[1][0][57]=s.arr[1][0][56];out.arr[1][0][58]=s.arr[1][0][57];out.arr[1][0][59]=s.arr[1][0][58];
out.arr[1][0][60]=s.arr[1][0][59];out.arr[1][0][61]=s.arr[1][0][60];out.arr[1][0][62]=s.arr[1][0][61];out.arr[1][0][63]=s.arr[1][0][62];out.arr[0][2][0]=s.arr[0][2][61];out.arr[0][2][1]=s.arr[0][2][62];out.arr[0][2][2]=s.arr[0][2][63];out.arr[0][2][3]=s.arr[0][2][0];out.arr[0][2][4]=s.arr[0][2][1];out.arr[0][2][5]=s.arr[0][2][2];
out.arr[0][2][6]=s.arr[0][2][3];out.arr[0][2][7]=s.arr[0][2][4];out.arr[0][2][8]=s.arr[0][2][5];out.arr[0][2][9]=s.arr[0][2][6];out.arr[0][2][10]=s.arr[0][2][7];out.arr[0][2][11]=s.arr[0][2][8];out.arr[0][2][12]=s.arr[0][2][9];out.arr[0][2][13]=s.arr[0][2][10];out.arr[0][2][14]=s.arr[0][2][11];out.arr[0][2][15]=s.arr[0][2][12];
out.arr[0][2][16]=s.arr[0][2][13];out.arr[0][2][17]=s.arr[0][2][14];out.arr[0][2][18]=s.arr[0][2][15];out.arr[0][2][19]=s.arr[0][2][16];out.arr[0][2][20]=s.arr[0][2][17];out.arr[0][2][21]=s.arr[0][2][18];out.arr[0][2][22]=s.arr[0][2][19];out.arr[0][2][23]=s.arr[0][2][20];out.arr[0][2][24]=s.arr[0][2][21];out.arr[0][2][25]=s.arr[0][2][22];
out.arr[0][2][26]=s.arr[0][2][23];out.arr[0][2][27]=s.arr[0][2][24];out.arr[0][2][28]=s.arr[0][2][25];out.arr[0][2][29]=s.arr[0][2][26];out.arr[0][2][30]=s.arr[0][2][27];out.arr[0][2][31]=s.arr[0][2][28];out.arr[0][2][32]=s.arr[0][2][29];out.arr[0][2][33]=s.arr[0][2][30];out.arr[0][2][34]=s.arr[0][2][31];out.arr[0][2][35]=s.arr[0][2][32];
out.arr[0][2][36]=s.arr[0][2][33];out.arr[0][2][37]=s.arr[0][2][34];out.arr[0][2][38]=s.arr[0][2][35];out.arr[0][2][39]=s.arr[0][2][36];out.arr[0][2][40]=s.arr[0][2][37];out.arr[0][2][41]=s.arr[0][2][38];out.arr[0][2][42]=s.arr[0][2][39];out.arr[0][2][43]=s.arr[0][2][40];out.arr[0][2][44]=s.arr[0][2][41];out.arr[0][2][45]=s.arr[0][2][42];
out.arr[0][2][46]=s.arr[0][2][43];out.arr[0][2][47]=s.arr[0][2][44];out.arr[0][2][48]=s.arr[0][2][45];out.arr[0][2][49]=s.arr[0][2][46];out.arr[0][2][50]=s.arr[0][2][47];out.arr[0][2][51]=s.arr[0][2][48];out.arr[0][2][52]=s.arr[0][2][49];out.arr[0][2][53]=s.arr[0][2][50];out.arr[0][2][54]=s.arr[0][2][51];out.arr[0][2][55]=s.arr[0][2][52];
out.arr[0][2][56]=s.arr[0][2][53];out.arr[0][2][57]=s.arr[0][2][54];out.arr[0][2][58]=s.arr[0][2][55];out.arr[0][2][59]=s.arr[0][2][56];out.arr[0][2][60]=s.arr[0][2][57];out.arr[0][2][61]=s.arr[0][2][58];out.arr[0][2][62]=s.arr[0][2][59];out.arr[0][2][63]=s.arr[0][2][60];out.arr[2][1][0]=s.arr[2][1][58];out.arr[2][1][1]=s.arr[2][1][59];
out.arr[2][1][2]=s.arr[2][1][60];out.arr[2][1][3]=s.arr[2][1][61];out.arr[2][1][4]=s.arr[2][1][62];out.arr[2][1][5]=s.arr[2][1][63];out.arr[2][1][6]=s.arr[2][1][0];out.arr[2][1][7]=s.arr[2][1][1];out.arr[2][1][8]=s.arr[2][1][2];out.arr[2][1][9]=s.arr[2][1][3];out.arr[2][1][10]=s.arr[2][1][4];out.arr[2][1][11]=s.arr[2][1][5];
out.arr[2][1][12]=s.arr[2][1][6];out.arr[2][1][13]=s.arr[2][1][7];out.arr[2][1][14]=s.arr[2][1][8];out.arr[2][1][15]=s.arr[2][1][9];out.arr[2][1][16]=s.arr[2][1][10];out.arr[2][1][17]=s.arr[2][1][11];out.arr[2][1][18]=s.arr[2][1][12];out.arr[2][1][19]=s.arr[2][1][13];out.arr[2][1][20]=s.arr[2][1][14];out.arr[2][1][21]=s.arr[2][1][15];
out.arr[2][1][22]=s.arr[2][1][16];out.arr[2][1][23]=s.arr[2][1][17];out.arr[2][1][24]=s.arr[2][1][18];out.arr[2][1][25]=s.arr[2][1][19];out.arr[2][1][26]=s.arr[2][1][20];out.arr[2][1][27]=s.arr[2][1][21];out.arr[2][1][28]=s.arr[2][1][22];out.arr[2][1][29]=s.arr[2][1][23];out.arr[2][1][30]=s.arr[2][1][24];out.arr[2][1][31]=s.arr[2][1][25];
out.arr[2][1][32]=s.arr[2][1][26];out.arr[2][1][33]=s.arr[2][1][27];out.arr[2][1][34]=s.arr[2][1][28];out.arr[2][1][35]=s.arr[2][1][29];out.arr[2][1][36]=s.arr[2][1][30];out.arr[2][1][37]=s.arr[2][1][31];out.arr[2][1][38]=s.arr[2][1][32];out.arr[2][1][39]=s.arr[2][1][33];out.arr[2][1][40]=s.arr[2][1][34];out.arr[2][1][41]=s.arr[2][1][35];
out.arr[2][1][42]=s.arr[2][1][36];out.arr[2][1][43]=s.arr[2][1][37];out.arr[2][1][44]=s.arr[2][1][38];out.arr[2][1][45]=s.arr[2][1][39];out.arr[2][1][46]=s.arr[2][1][40];out.arr[2][1][47]=s.arr[2][1][41];out.arr[2][1][48]=s.arr[2][1][42];out.arr[2][1][49]=s.arr[2][1][43];out.arr[2][1][50]=s.arr[2][1][44];out.arr[2][1][51]=s.arr[2][1][45];
out.arr[2][1][52]=s.arr[2][1][46];out.arr[2][1][53]=s.arr[2][1][47];out.arr[2][1][54]=s.arr[2][1][48];out.arr[2][1][55]=s.arr[2][1][49];out.arr[2][1][56]=s.arr[2][1][50];out.arr[2][1][57]=s.arr[2][1][51];out.arr[2][1][58]=s.arr[2][1][52];out.arr[2][1][59]=s.arr[2][1][53];out.arr[2][1][60]=s.arr[2][1][54];out.arr[2][1][61]=s.arr[2][1][55];
out.arr[2][1][62]=s.arr[2][1][56];out.arr[2][1][63]=s.arr[2][1][57];out.arr[1][2][0]=s.arr[1][2][54];out.arr[1][2][1]=s.arr[1][2][55];out.arr[1][2][2]=s.arr[1][2][56];out.arr[1][2][3]=s.arr[1][2][57];out.arr[1][2][4]=s.arr[1][2][58];out.arr[1][2][5]=s.arr[1][2][59];out.arr[1][2][6]=s.arr[1][2][60];out.arr[1][2][7]=s.arr[1][2][61];
out.arr[1][2][8]=s.arr[1][2][62];out.arr[1][2][9]=s.arr[1][2][63];out.arr[1][2][10]=s.arr[1][2][0];out.arr[1][2][11]=s.arr[1][2][1];out.arr[1][2][12]=s.arr[1][2][2];out.arr[1][2][13]=s.arr[1][2][3];out.arr[1][2][14]=s.arr[1][2][4];out.arr[1][2][15]=s.arr[1][2][5];out.arr[1][2][16]=s.arr[1][2][6];out.arr[1][2][17]=s.arr[1][2][7];
out.arr[1][2][18]=s.arr[1][2][8];out.arr[1][2][19]=s.arr[1][2][9];out.arr[1][2][20]=s.arr[1][2][10];out.arr[1][2][21]=s.arr[1][2][11];out.arr[1][2][22]=s.arr[1][2][12];out.arr[1][2][23]=s.arr[1][2][13];out.arr[1][2][24]=s.arr[1][2][14];out.arr[1][2][25]=s.arr[1][2][15];out.arr[1][2][26]=s.arr[1][2][16];out.arr[1][2][27]=s.arr[1][2][17];
out.arr[1][2][28]=s.arr[1][2][18];out.arr[1][2][29]=s.arr[1][2][19];out.arr[1][2][30]=s.arr[1][2][20];out.arr[1][2][31]=s.arr[1][2][21];out.arr[1][2][32]=s.arr[1][2][22];out.arr[1][2][33]=s.arr[1][2][23];out.arr[1][2][34]=s.arr[1][2][24];out.arr[1][2][35]=s.arr[1][2][25];out.arr[1][2][36]=s.arr[1][2][26];out.arr[1][2][37]=s.arr[1][2][27];
out.arr[1][2][38]=s.arr[1][2][28];out.arr[1][2][39]=s.arr[1][2][29];out.arr[1][2][40]=s.arr[1][2][30];out.arr[1][2][41]=s.arr[1][2][31];out.arr[1][2][42]=s.arr[1][2][32];out.arr[1][2][43]=s.arr[1][2][33];out.arr[1][2][44]=s.arr[1][2][34];out.arr[1][2][45]=s.arr[1][2][35];out.arr[1][2][46]=s.arr[1][2][36];out.arr[1][2][47]=s.arr[1][2][37];
out.arr[1][2][48]=s.arr[1][2][38];out.arr[1][2][49]=s.arr[1][2][39];out.arr[1][2][50]=s.arr[1][2][40];out.arr[1][2][51]=s.arr[1][2][41];out.arr[1][2][52]=s.arr[1][2][42];out.arr[1][2][53]=s.arr[1][2][43];out.arr[1][2][54]=s.arr[1][2][44];out.arr[1][2][55]=s.arr[1][2][45];out.arr[1][2][56]=s.arr[1][2][46];out.arr[1][2][57]=s.arr[1][2][47];
out.arr[1][2][58]=s.arr[1][2][48];out.arr[1][2][59]=s.arr[1][2][49];out.arr[1][2][60]=s.arr[1][2][50];out.arr[1][2][61]=s.arr[1][2][51];out.arr[1][2][62]=s.arr[1][2][52];out.arr[1][2][63]=s.arr[1][2][53];out.arr[2][3][0]=s.arr[2][3][49];out.arr[2][3][1]=s.arr[2][3][50];out.arr[2][3][2]=s.arr[2][3][51];out.arr[2][3][3]=s.arr[2][3][52];
out.arr[2][3][4]=s.arr[2][3][53];out.arr[2][3][5]=s.arr[2][3][54];out.arr[2][3][6]=s.arr[2][3][55];out.arr[2][3][7]=s.arr[2][3][56];out.arr[2][3][8]=s.arr[2][3][57];out.arr[2][3][9]=s.arr[2][3][58];out.arr[2][3][10]=s.arr[2][3][59];out.arr[2][3][11]=s.arr[2][3][60];out.arr[2][3][12]=s.arr[2][3][61];out.arr[2][3][13]=s.arr[2][3][62];
out.arr[2][3][14]=s.arr[2][3][63];out.arr[2][3][15]=s.arr[2][3][0];out.arr[2][3][16]=s.arr[2][3][1];out.arr[2][3][17]=s.arr[2][3][2];out.arr[2][3][18]=s.arr[2][3][3];out.arr[2][3][19]=s.arr[2][3][4];out.arr[2][3][20]=s.arr[2][3][5];out.arr[2][3][21]=s.arr[2][3][6];out.arr[2][3][22]=s.arr[2][3][7];out.arr[2][3][23]=s.arr[2][3][8];
out.arr[2][3][24]=s.arr[2][3][9];out.arr[2][3][25]=s.arr[2][3][10];out.arr[2][3][26]=s.arr[2][3][11];out.arr[2][3][27]=s.arr[2][3][12];out.arr[2][3][28]=s.arr[2][3][13];out.arr[2][3][29]=s.arr[2][3][14];out.arr[2][3][30]=s.arr[2][3][15];out.arr[2][3][31]=s.arr[2][3][16];out.arr[2][3][32]=s.arr[2][3][17];out.arr[2][3][33]=s.arr[2][3][18];
out.arr[2][3][34]=s.arr[2][3][19];out.arr[2][3][35]=s.arr[2][3][20];out.arr[2][3][36]=s.arr[2][3][21];out.arr[2][3][37]=s.arr[2][3][22];out.arr[2][3][38]=s.arr[2][3][23];out.arr[2][3][39]=s.arr[2][3][24];out.arr[2][3][40]=s.arr[2][3][25];out.arr[2][3][41]=s.arr[2][3][26];out.arr[2][3][42]=s.arr[2][3][27];out.arr[2][3][43]=s.arr[2][3][28];
out.arr[2][3][44]=s.arr[2][3][29];out.arr[2][3][45]=s.arr[2][3][30];out.arr[2][3][46]=s.arr[2][3][31];out.arr[2][3][47]=s.arr[2][3][32];out.arr[2][3][48]=s.arr[2][3][33];out.arr[2][3][49]=s.arr[2][3][34];out.arr[2][3][50]=s.arr[2][3][35];out.arr[2][3][51]=s.arr[2][3][36];out.arr[2][3][52]=s.arr[2][3][37];out.arr[2][3][53]=s.arr[2][3][38];
out.arr[2][3][54]=s.arr[2][3][39];out.arr[2][3][55]=s.arr[2][3][40];out.arr[2][3][56]=s.arr[2][3][41];out.arr[2][3][57]=s.arr[2][3][42];out.arr[2][3][58]=s.arr[2][3][43];out.arr[2][3][59]=s.arr[2][3][44];out.arr[2][3][60]=s.arr[2][3][45];out.arr[2][3][61]=s.arr[2][3][46];out.arr[2][3][62]=s.arr[2][3][47];out.arr[2][3][63]=s.arr[2][3][48];
out.arr[3][3][0]=s.arr[3][3][43];out.arr[3][3][1]=s.arr[3][3][44];out.arr[3][3][2]=s.arr[3][3][45];out.arr[3][3][3]=s.arr[3][3][46];out.arr[3][3][4]=s.arr[3][3][47];out.arr[3][3][5]=s.arr[3][3][48];out.arr[3][3][6]=s.arr[3][3][49];out.arr[3][3][7]=s.arr[3][3][50];out.arr[3][3][8]=s.arr[3][3][51];out.arr[3][3][9]=s.arr[3][3][52];
out.arr[3][3][10]=s.arr[3][3][53];out.arr[3][3][11]=s.arr[3][3][54];out.arr[3][3][12]=s.arr[3][3][55];out.arr[3][3][13]=s.arr[3][3][56];out.arr[3][3][14]=s.arr[3][3][57];out.arr[3][3][15]=s.arr[3][3][58];out.arr[3][3][16]=s.arr[3][3][59];out.arr[3][3][17]=s.arr[3][3][60];out.arr[3][3][18]=s.arr[3][3][61];out.arr[3][3][19]=s.arr[3][3][62];
out.arr[3][3][20]=s.arr[3][3][63];out.arr[3][3][21]=s.arr[3][3][0];out.arr[3][3][22]=s.arr[3][3][1];out.arr[3][3][23]=s.arr[3][3][2];out.arr[3][3][24]=s.arr[3][3][3];out.arr[3][3][25]=s.arr[3][3][4];out.arr[3][3][26]=s.arr[3][3][5];out.arr[3][3][27]=s.arr[3][3][6];out.arr[3][3][28]=s.arr[3][3][7];out.arr[3][3][29]=s.arr[3][3][8];
out.arr[3][3][30]=s.arr[3][3][9];out.arr[3][3][31]=s.arr[3][3][10];out.arr[3][3][32]=s.arr[3][3][11];out.arr[3][3][33]=s.arr[3][3][12];out.arr[3][3][34]=s.arr[3][3][13];out.arr[3][3][35]=s.arr[3][3][14];out.arr[3][3][36]=s.arr[3][3][15];out.arr[3][3][37]=s.arr[3][3][16];out.arr[3][3][38]=s.arr[3][3][17];out.arr[3][3][39]=s.arr[3][3][18];
out.arr[3][3][40]=s.arr[3][3][19];out.arr[3][3][41]=s.arr[3][3][20];out.arr[3][3][42]=s.arr[3][3][21];out.arr[3][3][43]=s.arr[3][3][22];out.arr[3][3][44]=s.arr[3][3][23];out.arr[3][3][45]=s.arr[3][3][24];out.arr[3][3][46]=s.arr[3][3][25];out.arr[3][3][47]=s.arr[3][3][26];out.arr[3][3][48]=s.arr[3][3][27];out.arr[3][3][49]=s.arr[3][3][28];
out.arr[3][3][50]=s.arr[3][3][29];out.arr[3][3][51]=s.arr[3][3][30];out.arr[3][3][52]=s.arr[3][3][31];out.arr[3][3][53]=s.arr[3][3][32];out.arr[3][3][54]=s.arr[3][3][33];out.arr[3][3][55]=s.arr[3][3][34];out.arr[3][3][56]=s.arr[3][3][35];out.arr[3][3][57]=s.arr[3][3][36];out.arr[3][3][58]=s.arr[3][3][37];out.arr[3][3][59]=s.arr[3][3][38];
out.arr[3][3][60]=s.arr[3][3][39];out.arr[3][3][61]=s.arr[3][3][40];out.arr[3][3][62]=s.arr[3][3][41];out.arr[3][3][63]=s.arr[3][3][42];out.arr[3][0][0]=s.arr[3][0][36];out.arr[3][0][1]=s.arr[3][0][37];out.arr[3][0][2]=s.arr[3][0][38];out.arr[3][0][3]=s.arr[3][0][39];out.arr[3][0][4]=s.arr[3][0][40];out.arr[3][0][5]=s.arr[3][0][41];
out.arr[3][0][6]=s.arr[3][0][42];out.arr[3][0][7]=s.arr[3][0][43];out.arr[3][0][8]=s.arr[3][0][44];out.arr[3][0][9]=s.arr[3][0][45];out.arr[3][0][10]=s.arr[3][0][46];out.arr[3][0][11]=s.arr[3][0][47];out.arr[3][0][12]=s.arr[3][0][48];out.arr[3][0][13]=s.arr[3][0][49];out.arr[3][0][14]=s.arr[3][0][50];out.arr[3][0][15]=s.arr[3][0][51];
out.arr[3][0][16]=s.arr[3][0][52];out.arr[3][0][17]=s.arr[3][0][53];out.arr[3][0][18]=s.arr[3][0][54];out.arr[3][0][19]=s.arr[3][0][55];out.arr[3][0][20]=s.arr[3][0][56];out.arr[3][0][21]=s.arr[3][0][57];out.arr[3][0][22]=s.arr[3][0][58];out.arr[3][0][23]=s.arr[3][0][59];out.arr[3][0][24]=s.arr[3][0][60];out.arr[3][0][25]=s.arr[3][0][61];
out.arr[3][0][26]=s.arr[3][0][62];out.arr[3][0][27]=s.arr[3][0][63];out.arr[3][0][28]=s.arr[3][0][0];out.arr[3][0][29]=s.arr[3][0][1];out.arr[3][0][30]=s.arr[3][0][2];out.arr[3][0][31]=s.arr[3][0][3];out.arr[3][0][32]=s.arr[3][0][4];out.arr[3][0][33]=s.arr[3][0][5];out.arr[3][0][34]=s.arr[3][0][6];out.arr[3][0][35]=s.arr[3][0][7];
out.arr[3][0][36]=s.arr[3][0][8];out.arr[3][0][37]=s.arr[3][0][9];out.arr[3][0][38]=s.arr[3][0][10];out.arr[3][0][39]=s.arr[3][0][11];out.arr[3][0][40]=s.arr[3][0][12];out.arr[3][0][41]=s.arr[3][0][13];out.arr[3][0][42]=s.arr[3][0][14];out.arr[3][0][43]=s.arr[3][0][15];out.arr[3][0][44]=s.arr[3][0][16];out.arr[3][0][45]=s.arr[3][0][17];
out.arr[3][0][46]=s.arr[3][0][18];out.arr[3][0][47]=s.arr[3][0][19];out.arr[3][0][48]=s.arr[3][0][20];out.arr[3][0][49]=s.arr[3][0][21];out.arr[3][0][50]=s.arr[3][0][22];out.arr[3][0][51]=s.arr[3][0][23];out.arr[3][0][52]=s.arr[3][0][24];out.arr[3][0][53]=s.arr[3][0][25];out.arr[3][0][54]=s.arr[3][0][26];out.arr[3][0][55]=s.arr[3][0][27];
out.arr[3][0][56]=s.arr[3][0][28];out.arr[3][0][57]=s.arr[3][0][29];out.arr[3][0][58]=s.arr[3][0][30];out.arr[3][0][59]=s.arr[3][0][31];out.arr[3][0][60]=s.arr[3][0][32];out.arr[3][0][61]=s.arr[3][0][33];out.arr[3][0][62]=s.arr[3][0][34];out.arr[3][0][63]=s.arr[3][0][35];out.arr[0][1][0]=s.arr[0][1][28];out.arr[0][1][1]=s.arr[0][1][29];
out.arr[0][1][2]=s.arr[0][1][30];out.arr[0][1][3]=s.arr[0][1][31];out.arr[0][1][4]=s.arr[0][1][32];out.arr[0][1][5]=s.arr[0][1][33];out.arr[0][1][6]=s.arr[0][1][34];out.arr[0][1][7]=s.arr[0][1][35];out.arr[0][1][8]=s.arr[0][1][36];out.arr[0][1][9]=s.arr[0][1][37];out.arr[0][1][10]=s.arr[0][1][38];out.arr[0][1][11]=s.arr[0][1][39];
out.arr[0][1][12]=s.arr[0][1][40];out.arr[0][1][13]=s.arr[0][1][41];out.arr[0][1][14]=s.arr[0][1][42];out.arr[0][1][15]=s.arr[0][1][43];out.arr[0][1][16]=s.arr[0][1][44];out.arr[0][1][17]=s.arr[0][1][45];out.arr[0][1][18]=s.arr[0][1][46];out.arr[0][1][19]=s.arr[0][1][47];out.arr[0][1][20]=s.arr[0][1][48];out.arr[0][1][21]=s.arr[0][1][49];
out.arr[0][1][22]=s.arr[0][1][50];out.arr[0][1][23]=s.arr[0][1][51];out.arr[0][1][24]=s.arr[0][1][52];out.arr[0][1][25]=s.arr[0][1][53];out.arr[0][1][26]=s.arr[0][1][54];out.arr[0][1][27]=s.arr[0][1][55];out.arr[0][1][28]=s.arr[0][1][56];out.arr[0][1][29]=s.arr[0][1][57];out.arr[0][1][30]=s.arr[0][1][58];out.arr[0][1][31]=s.arr[0][1][59];
out.arr[0][1][32]=s.arr[0][1][60];out.arr[0][1][33]=s.arr[0][1][61];out.arr[0][1][34]=s.arr[0][1][62];out.arr[0][1][35]=s.arr[0][1][63];out.arr[0][1][36]=s.arr[0][1][0];out.arr[0][1][37]=s.arr[0][1][1];out.arr[0][1][38]=s.arr[0][1][2];out.arr[0][1][39]=s.arr[0][1][3];out.arr[0][1][40]=s.arr[0][1][4];out.arr[0][1][41]=s.arr[0][1][5];
out.arr[0][1][42]=s.arr[0][1][6];out.arr[0][1][43]=s.arr[0][1][7];out.arr[0][1][44]=s.arr[0][1][8];out.arr[0][1][45]=s.arr[0][1][9];out.arr[0][1][46]=s.arr[0][1][10];out.arr[0][1][47]=s.arr[0][1][11];out.arr[0][1][48]=s.arr[0][1][12];out.arr[0][1][49]=s.arr[0][1][13];out.arr[0][1][50]=s.arr[0][1][14];out.arr[0][1][51]=s.arr[0][1][15];
out.arr[0][1][52]=s.arr[0][1][16];out.arr[0][1][53]=s.arr[0][1][17];out.arr[0][1][54]=s.arr[0][1][18];out.arr[0][1][55]=s.arr[0][1][19];out.arr[0][1][56]=s.arr[0][1][20];out.arr[0][1][57]=s.arr[0][1][21];out.arr[0][1][58]=s.arr[0][1][22];out.arr[0][1][59]=s.arr[0][1][23];out.arr[0][1][60]=s.arr[0][1][24];out.arr[0][1][61]=s.arr[0][1][25];
out.arr[0][1][62]=s.arr[0][1][26];out.arr[0][1][63]=s.arr[0][1][27];out.arr[1][3][0]=s.arr[1][3][19];out.arr[1][3][1]=s.arr[1][3][20];out.arr[1][3][2]=s.arr[1][3][21];out.arr[1][3][3]=s.arr[1][3][22];out.arr[1][3][4]=s.arr[1][3][23];out.arr[1][3][5]=s.arr[1][3][24];out.arr[1][3][6]=s.arr[1][3][25];out.arr[1][3][7]=s.arr[1][3][26];
out.arr[1][3][8]=s.arr[1][3][27];out.arr[1][3][9]=s.arr[1][3][28];out.arr[1][3][10]=s.arr[1][3][29];out.arr[1][3][11]=s.arr[1][3][30];out.arr[1][3][12]=s.arr[1][3][31];out.arr[1][3][13]=s.arr[1][3][32];out.arr[1][3][14]=s.arr[1][3][33];out.arr[1][3][15]=s.arr[1][3][34];out.arr[1][3][16]=s.arr[1][3][35];out.arr[1][3][17]=s.arr[1][3][36];
out.arr[1][3][18]=s.arr[1][3][37];out.arr[1][3][19]=s.arr[1][3][38];out.arr[1][3][20]=s.arr[1][3][39];out.arr[1][3][21]=s.arr[1][3][40];out.arr[1][3][22]=s.arr[1][3][41];out.arr[1][3][23]=s.arr[1][3][42];out.arr[1][3][24]=s.arr[1][3][43];out.arr[1][3][25]=s.arr[1][3][44];out.arr[1][3][26]=s.arr[1][3][45];out.arr[1][3][27]=s.arr[1][3][46];
out.arr[1][3][28]=s.arr[1][3][47];out.arr[1][3][29]=s.arr[1][3][48];out.arr[1][3][30]=s.arr[1][3][49];out.arr[1][3][31]=s.arr[1][3][50];out.arr[1][3][32]=s.arr[1][3][51];out.arr[1][3][33]=s.arr[1][3][52];out.arr[1][3][34]=s.arr[1][3][53];out.arr[1][3][35]=s.arr[1][3][54];out.arr[1][3][36]=s.arr[1][3][55];out.arr[1][3][37]=s.arr[1][3][56];
out.arr[1][3][38]=s.arr[1][3][57];out.arr[1][3][39]=s.arr[1][3][58];out.arr[1][3][40]=s.arr[1][3][59];out.arr[1][3][41]=s.arr[1][3][60];out.arr[1][3][42]=s.arr[1][3][61];out.arr[1][3][43]=s.arr[1][3][62];out.arr[1][3][44]=s.arr[1][3][63];out.arr[1][3][45]=s.arr[1][3][0];out.arr[1][3][46]=s.arr[1][3][1];out.arr[1][3][47]=s.arr[1][3][2];
out.arr[1][3][48]=s.arr[1][3][3];out.arr[1][3][49]=s.arr[1][3][4];out.arr[1][3][50]=s.arr[1][3][5];out.arr[1][3][51]=s.arr[1][3][6];out.arr[1][3][52]=s.arr[1][3][7];out.arr[1][3][53]=s.arr[1][3][8];out.arr[1][3][54]=s.arr[1][3][9];out.arr[1][3][55]=s.arr[1][3][10];out.arr[1][3][56]=s.arr[1][3][11];out.arr[1][3][57]=s.arr[1][3][12];
out.arr[1][3][58]=s.arr[1][3][13];out.arr[1][3][59]=s.arr[1][3][14];out.arr[1][3][60]=s.arr[1][3][15];out.arr[1][3][61]=s.arr[1][3][16];out.arr[1][3][62]=s.arr[1][3][17];out.arr[1][3][63]=s.arr[1][3][18];out.arr[3][1][0]=s.arr[3][1][9];out.arr[3][1][1]=s.arr[3][1][10];out.arr[3][1][2]=s.arr[3][1][11];out.arr[3][1][3]=s.arr[3][1][12];
out.arr[3][1][4]=s.arr[3][1][13];out.arr[3][1][5]=s.arr[3][1][14];out.arr[3][1][6]=s.arr[3][1][15];out.arr[3][1][7]=s.arr[3][1][16];out.arr[3][1][8]=s.arr[3][1][17];out.arr[3][1][9]=s.arr[3][1][18];out.arr[3][1][10]=s.arr[3][1][19];out.arr[3][1][11]=s.arr[3][1][20];out.arr[3][1][12]=s.arr[3][1][21];out.arr[3][1][13]=s.arr[3][1][22];
out.arr[3][1][14]=s.arr[3][1][23];out.arr[3][1][15]=s.arr[3][1][24];out.arr[3][1][16]=s.arr[3][1][25];out.arr[3][1][17]=s.arr[3][1][26];out.arr[3][1][18]=s.arr[3][1][27];out.arr[3][1][19]=s.arr[3][1][28];out.arr[3][1][20]=s.arr[3][1][29];out.arr[3][1][21]=s.arr[3][1][30];out.arr[3][1][22]=s.arr[3][1][31];out.arr[3][1][23]=s.arr[3][1][32];
out.arr[3][1][24]=s.arr[3][1][33];out.arr[3][1][25]=s.arr[3][1][34];out.arr[3][1][26]=s.arr[3][1][35];out.arr[3][1][27]=s.arr[3][1][36];out.arr[3][1][28]=s.arr[3][1][37];out.arr[3][1][29]=s.arr[3][1][38];out.arr[3][1][30]=s.arr[3][1][39];out.arr[3][1][31]=s.arr[3][1][40];out.arr[3][1][32]=s.arr[3][1][41];out.arr[3][1][33]=s.arr[3][1][42];
out.arr[3][1][34]=s.arr[3][1][43];out.arr[3][1][35]=s.arr[3][1][44];out.arr[3][1][36]=s.arr[3][1][45];out.arr[3][1][37]=s.arr[3][1][46];out.arr[3][1][38]=s.arr[3][1][47];out.arr[3][1][39]=s.arr[3][1][48];out.arr[3][1][40]=s.arr[3][1][49];out.arr[3][1][41]=s.arr[3][1][50];out.arr[3][1][42]=s.arr[3][1][51];out.arr[3][1][43]=s.arr[3][1][52];
out.arr[3][1][44]=s.arr[3][1][53];out.arr[3][1][45]=s.arr[3][1][54];out.arr[3][1][46]=s.arr[3][1][55];out.arr[3][1][47]=s.arr[3][1][56];out.arr[3][1][48]=s.arr[3][1][57];out.arr[3][1][49]=s.arr[3][1][58];out.arr[3][1][50]=s.arr[3][1][59];out.arr[3][1][51]=s.arr[3][1][60];out.arr[3][1][52]=s.arr[3][1][61];out.arr[3][1][53]=s.arr[3][1][62];
out.arr[3][1][54]=s.arr[3][1][63];out.arr[3][1][55]=s.arr[3][1][0];out.arr[3][1][56]=s.arr[3][1][1];out.arr[3][1][57]=s.arr[3][1][2];out.arr[3][1][58]=s.arr[3][1][3];out.arr[3][1][59]=s.arr[3][1][4];out.arr[3][1][60]=s.arr[3][1][5];out.arr[3][1][61]=s.arr[3][1][6];out.arr[3][1][62]=s.arr[3][1][7];out.arr[3][1][63]=s.arr[3][1][8];
out.arr[1][4][0]=s.arr[1][4][62];out.arr[1][4][1]=s.arr[1][4][63];out.arr[1][4][2]=s.arr[1][4][0];out.arr[1][4][3]=s.arr[1][4][1];out.arr[1][4][4]=s.arr[1][4][2];out.arr[1][4][5]=s.arr[1][4][3];out.arr[1][4][6]=s.arr[1][4][4];out.arr[1][4][7]=s.arr[1][4][5];out.arr[1][4][8]=s.arr[1][4][6];out.arr[1][4][9]=s.arr[1][4][7];
out.arr[1][4][10]=s.arr[1][4][8];out.arr[1][4][11]=s.arr[1][4][9];out.arr[1][4][12]=s.arr[1][4][10];out.arr[1][4][13]=s.arr[1][4][11];out.arr[1][4][14]=s.arr[1][4][12];out.arr[1][4][15]=s.arr[1][4][13];out.arr[1][4][16]=s.arr[1][4][14];out.arr[1][4][17]=s.arr[1][4][15];out.arr[1][4][18]=s.arr[1][4][16];out.arr[1][4][19]=s.arr[1][4][17];
out.arr[1][4][20]=s.arr[1][4][18];out.arr[1][4][21]=s.arr[1][4][19];out.arr[1][4][22]=s.arr[1][4][20];out.arr[1][4][23]=s.arr[1][4][21];out.arr[1][4][24]=s.arr[1][4][22];out.arr[1][4][25]=s.arr[1][4][23];out.arr[1][4][26]=s.arr[1][4][24];out.arr[1][4][27]=s.arr[1][4][25];out.arr[1][4][28]=s.arr[1][4][26];out.arr[1][4][29]=s.arr[1][4][27];
out.arr[1][4][30]=s.arr[1][4][28];out.arr[1][4][31]=s.arr[1][4][29];out.arr[1][4][32]=s.arr[1][4][30];out.arr[1][4][33]=s.arr[1][4][31];out.arr[1][4][34]=s.arr[1][4][32];out.arr[1][4][35]=s.arr[1][4][33];out.arr[1][4][36]=s.arr[1][4][34];out.arr[1][4][37]=s.arr[1][4][35];out.arr[1][4][38]=s.arr[1][4][36];out.arr[1][4][39]=s.arr[1][4][37];
out.arr[1][4][40]=s.arr[1][4][38];out.arr[1][4][41]=s.arr[1][4][39];out.arr[1][4][42]=s.arr[1][4][40];out.arr[1][4][43]=s.arr[1][4][41];out.arr[1][4][44]=s.arr[1][4][42];out.arr[1][4][45]=s.arr[1][4][43];out.arr[1][4][46]=s.arr[1][4][44];out.arr[1][4][47]=s.arr[1][4][45];out.arr[1][4][48]=s.arr[1][4][46];out.arr[1][4][49]=s.arr[1][4][47];
out.arr[1][4][50]=s.arr[1][4][48];out.arr[1][4][51]=s.arr[1][4][49];out.arr[1][4][52]=s.arr[1][4][50];out.arr[1][4][53]=s.arr[1][4][51];out.arr[1][4][54]=s.arr[1][4][52];out.arr[1][4][55]=s.arr[1][4][53];out.arr[1][4][56]=s.arr[1][4][54];out.arr[1][4][57]=s.arr[1][4][55];out.arr[1][4][58]=s.arr[1][4][56];out.arr[1][4][59]=s.arr[1][4][57];
out.arr[1][4][60]=s.arr[1][4][58];out.arr[1][4][61]=s.arr[1][4][59];out.arr[1][4][62]=s.arr[1][4][60];out.arr[1][4][63]=s.arr[1][4][61];out.arr[4][4][0]=s.arr[4][4][50];out.arr[4][4][1]=s.arr[4][4][51];out.arr[4][4][2]=s.arr[4][4][52];out.arr[4][4][3]=s.arr[4][4][53];out.arr[4][4][4]=s.arr[4][4][54];out.arr[4][4][5]=s.arr[4][4][55];
out.arr[4][4][6]=s.arr[4][4][56];out.arr[4][4][7]=s.arr[4][4][57];out.arr[4][4][8]=s.arr[4][4][58];out.arr[4][4][9]=s.arr[4][4][59];out.arr[4][4][10]=s.arr[4][4][60];out.arr[4][4][11]=s.arr[4][4][61];out.arr[4][4][12]=s.arr[4][4][62];out.arr[4][4][13]=s.arr[4][4][63];out.arr[4][4][14]=s.arr[4][4][0];out.arr[4][4][15]=s.arr[4][4][1];
out.arr[4][4][16]=s.arr[4][4][2];out.arr[4][4][17]=s.arr[4][4][3];out.arr[4][4][18]=s.arr[4][4][4];out.arr[4][4][19]=s.arr[4][4][5];out.arr[4][4][20]=s.arr[4][4][6];out.arr[4][4][21]=s.arr[4][4][7];out.arr[4][4][22]=s.arr[4][4][8];out.arr[4][4][23]=s.arr[4][4][9];out.arr[4][4][24]=s.arr[4][4][10];out.arr[4][4][25]=s.arr[4][4][11];
out.arr[4][4][26]=s.arr[4][4][12];out.arr[4][4][27]=s.arr[4][4][13];out.arr[4][4][28]=s.arr[4][4][14];out.arr[4][4][29]=s.arr[4][4][15];out.arr[4][4][30]=s.arr[4][4][16];out.arr[4][4][31]=s.arr[4][4][17];out.arr[4][4][32]=s.arr[4][4][18];out.arr[4][4][33]=s.arr[4][4][19];out.arr[4][4][34]=s.arr[4][4][20];out.arr[4][4][35]=s.arr[4][4][21];
out.arr[4][4][36]=s.arr[4][4][22];out.arr[4][4][37]=s.arr[4][4][23];out.arr[4][4][38]=s.arr[4][4][24];out.arr[4][4][39]=s.arr[4][4][25];out.arr[4][4][40]=s.arr[4][4][26];out.arr[4][4][41]=s.arr[4][4][27];out.arr[4][4][42]=s.arr[4][4][28];out.arr[4][4][43]=s.arr[4][4][29];out.arr[4][4][44]=s.arr[4][4][30];out.arr[4][4][45]=s.arr[4][4][31];
out.arr[4][4][46]=s.arr[4][4][32];out.arr[4][4][47]=s.arr[4][4][33];out.arr[4][4][48]=s.arr[4][4][34];out.arr[4][4][49]=s.arr[4][4][35];out.arr[4][4][50]=s.arr[4][4][36];out.arr[4][4][51]=s.arr[4][4][37];out.arr[4][4][52]=s.arr[4][4][38];out.arr[4][4][53]=s.arr[4][4][39];out.arr[4][4][54]=s.arr[4][4][40];out.arr[4][4][55]=s.arr[4][4][41];
out.arr[4][4][56]=s.arr[4][4][42];out.arr[4][4][57]=s.arr[4][4][43];out.arr[4][4][58]=s.arr[4][4][44];out.arr[4][4][59]=s.arr[4][4][45];out.arr[4][4][60]=s.arr[4][4][46];out.arr[4][4][61]=s.arr[4][4][47];out.arr[4][4][62]=s.arr[4][4][48];out.arr[4][4][63]=s.arr[4][4][49];out.arr[4][0][0]=s.arr[4][0][37];out.arr[4][0][1]=s.arr[4][0][38];
out.arr[4][0][2]=s.arr[4][0][39];out.arr[4][0][3]=s.arr[4][0][40];out.arr[4][0][4]=s.arr[4][0][41];out.arr[4][0][5]=s.arr[4][0][42];out.arr[4][0][6]=s.arr[4][0][43];out.arr[4][0][7]=s.arr[4][0][44];out.arr[4][0][8]=s.arr[4][0][45];out.arr[4][0][9]=s.arr[4][0][46];out.arr[4][0][10]=s.arr[4][0][47];out.arr[4][0][11]=s.arr[4][0][48];
out.arr[4][0][12]=s.arr[4][0][49];out.arr[4][0][13]=s.arr[4][0][50];out.arr[4][0][14]=s.arr[4][0][51];out.arr[4][0][15]=s.arr[4][0][52];out.arr[4][0][16]=s.arr[4][0][53];out.arr[4][0][17]=s.arr[4][0][54];out.arr[4][0][18]=s.arr[4][0][55];out.arr[4][0][19]=s.arr[4][0][56];out.arr[4][0][20]=s.arr[4][0][57];out.arr[4][0][21]=s.arr[4][0][58];
out.arr[4][0][22]=s.arr[4][0][59];out.arr[4][0][23]=s.arr[4][0][60];out.arr[4][0][24]=s.arr[4][0][61];out.arr[4][0][25]=s.arr[4][0][62];out.arr[4][0][26]=s.arr[4][0][63];out.arr[4][0][27]=s.arr[4][0][0];out.arr[4][0][28]=s.arr[4][0][1];out.arr[4][0][29]=s.arr[4][0][2];out.arr[4][0][30]=s.arr[4][0][3];out.arr[4][0][31]=s.arr[4][0][4];
out.arr[4][0][32]=s.arr[4][0][5];out.arr[4][0][33]=s.arr[4][0][6];out.arr[4][0][34]=s.arr[4][0][7];out.arr[4][0][35]=s.arr[4][0][8];out.arr[4][0][36]=s.arr[4][0][9];out.arr[4][0][37]=s.arr[4][0][10];out.arr[4][0][38]=s.arr[4][0][11];out.arr[4][0][39]=s.arr[4][0][12];out.arr[4][0][40]=s.arr[4][0][13];out.arr[4][0][41]=s.arr[4][0][14];
out.arr[4][0][42]=s.arr[4][0][15];out.arr[4][0][43]=s.arr[4][0][16];out.arr[4][0][44]=s.arr[4][0][17];out.arr[4][0][45]=s.arr[4][0][18];out.arr[4][0][46]=s.arr[4][0][19];out.arr[4][0][47]=s.arr[4][0][20];out.arr[4][0][48]=s.arr[4][0][21];out.arr[4][0][49]=s.arr[4][0][22];out.arr[4][0][50]=s.arr[4][0][23];out.arr[4][0][51]=s.arr[4][0][24];
out.arr[4][0][52]=s.arr[4][0][25];out.arr[4][0][53]=s.arr[4][0][26];out.arr[4][0][54]=s.arr[4][0][27];out.arr[4][0][55]=s.arr[4][0][28];out.arr[4][0][56]=s.arr[4][0][29];out.arr[4][0][57]=s.arr[4][0][30];out.arr[4][0][58]=s.arr[4][0][31];out.arr[4][0][59]=s.arr[4][0][32];out.arr[4][0][60]=s.arr[4][0][33];out.arr[4][0][61]=s.arr[4][0][34];
out.arr[4][0][62]=s.arr[4][0][35];out.arr[4][0][63]=s.arr[4][0][36];out.arr[0][3][0]=s.arr[0][3][23];out.arr[0][3][1]=s.arr[0][3][24];out.arr[0][3][2]=s.arr[0][3][25];out.arr[0][3][3]=s.arr[0][3][26];out.arr[0][3][4]=s.arr[0][3][27];out.arr[0][3][5]=s.arr[0][3][28];out.arr[0][3][6]=s.arr[0][3][29];out.arr[0][3][7]=s.arr[0][3][30];
out.arr[0][3][8]=s.arr[0][3][31];out.arr[0][3][9]=s.arr[0][3][32];out.arr[0][3][10]=s.arr[0][3][33];out.arr[0][3][11]=s.arr[0][3][34];out.arr[0][3][12]=s.arr[0][3][35];out.arr[0][3][13]=s.arr[0][3][36];out.arr[0][3][14]=s.arr[0][3][37];out.arr[0][3][15]=s.arr[0][3][38];out.arr[0][3][16]=s.arr[0][3][39];out.arr[0][3][17]=s.arr[0][3][40];
out.arr[0][3][18]=s.arr[0][3][41];out.arr[0][3][19]=s.arr[0][3][42];out.arr[0][3][20]=s.arr[0][3][43];out.arr[0][3][21]=s.arr[0][3][44];out.arr[0][3][22]=s.arr[0][3][45];out.arr[0][3][23]=s.arr[0][3][46];out.arr[0][3][24]=s.arr[0][3][47];out.arr[0][3][25]=s.arr[0][3][48];out.arr[0][3][26]=s.arr[0][3][49];out.arr[0][3][27]=s.arr[0][3][50];
out.arr[0][3][28]=s.arr[0][3][51];out.arr[0][3][29]=s.arr[0][3][52];out.arr[0][3][30]=s.arr[0][3][53];out.arr[0][3][31]=s.arr[0][3][54];out.arr[0][3][32]=s.arr[0][3][55];out.arr[0][3][33]=s.arr[0][3][56];out.arr[0][3][34]=s.arr[0][3][57];out.arr[0][3][35]=s.arr[0][3][58];out.arr[0][3][36]=s.arr[0][3][59];out.arr[0][3][37]=s.arr[0][3][60];
out.arr[0][3][38]=s.arr[0][3][61];out.arr[0][3][39]=s.arr[0][3][62];out.arr[0][3][40]=s.arr[0][3][63];out.arr[0][3][41]=s.arr[0][3][0];out.arr[0][3][42]=s.arr[0][3][1];out.arr[0][3][43]=s.arr[0][3][2];out.arr[0][3][44]=s.arr[0][3][3];out.arr[0][3][45]=s.arr[0][3][4];out.arr[0][3][46]=s.arr[0][3][5];out.arr[0][3][47]=s.arr[0][3][6];
out.arr[0][3][48]=s.arr[0][3][7];out.arr[0][3][49]=s.arr[0][3][8];out.arr[0][3][50]=s.arr[0][3][9];out.arr[0][3][51]=s.arr[0][3][10];out.arr[0][3][52]=s.arr[0][3][11];out.arr[0][3][53]=s.arr[0][3][12];out.arr[0][3][54]=s.arr[0][3][13];out.arr[0][3][55]=s.arr[0][3][14];out.arr[0][3][56]=s.arr[0][3][15];out.arr[0][3][57]=s.arr[0][3][16];
out.arr[0][3][58]=s.arr[0][3][17];out.arr[0][3][59]=s.arr[0][3][18];out.arr[0][3][60]=s.arr[0][3][19];out.arr[0][3][61]=s.arr[0][3][20];out.arr[0][3][62]=s.arr[0][3][21];out.arr[0][3][63]=s.arr[0][3][22];out.arr[3][4][0]=s.arr[3][4][8];out.arr[3][4][1]=s.arr[3][4][9];out.arr[3][4][2]=s.arr[3][4][10];out.arr[3][4][3]=s.arr[3][4][11];
out.arr[3][4][4]=s.arr[3][4][12];out.arr[3][4][5]=s.arr[3][4][13];out.arr[3][4][6]=s.arr[3][4][14];out.arr[3][4][7]=s.arr[3][4][15];out.arr[3][4][8]=s.arr[3][4][16];out.arr[3][4][9]=s.arr[3][4][17];out.arr[3][4][10]=s.arr[3][4][18];out.arr[3][4][11]=s.arr[3][4][19];out.arr[3][4][12]=s.arr[3][4][20];out.arr[3][4][13]=s.arr[3][4][21];
out.arr[3][4][14]=s.arr[3][4][22];out.arr[3][4][15]=s.arr[3][4][23];out.arr[3][4][16]=s.arr[3][4][24];out.arr[3][4][17]=s.arr[3][4][25];out.arr[3][4][18]=s.arr[3][4][26];out.arr[3][4][19]=s.arr[3][4][27];out.arr[3][4][20]=s.arr[3][4][28];out.arr[3][4][21]=s.arr[3][4][29];out.arr[3][4][22]=s.arr[3][4][30];out.arr[3][4][23]=s.arr[3][4][31];
out.arr[3][4][24]=s.arr[3][4][32];out.arr[3][4][25]=s.arr[3][4][33];out.arr[3][4][26]=s.arr[3][4][34];out.arr[3][4][27]=s.arr[3][4][35];out.arr[3][4][28]=s.arr[3][4][36];out.arr[3][4][29]=s.arr[3][4][37];out.arr[3][4][30]=s.arr[3][4][38];out.arr[3][4][31]=s.arr[3][4][39];out.arr[3][4][32]=s.arr[3][4][40];out.arr[3][4][33]=s.arr[3][4][41];
out.arr[3][4][34]=s.arr[3][4][42];out.arr[3][4][35]=s.arr[3][4][43];out.arr[3][4][36]=s.arr[3][4][44];out.arr[3][4][37]=s.arr[3][4][45];out.arr[3][4][38]=s.arr[3][4][46];out.arr[3][4][39]=s.arr[3][4][47];out.arr[3][4][40]=s.arr[3][4][48];out.arr[3][4][41]=s.arr[3][4][49];out.arr[3][4][42]=s.arr[3][4][50];out.arr[3][4][43]=s.arr[3][4][51];
out.arr[3][4][44]=s.arr[3][4][52];out.arr[3][4][45]=s.arr[3][4][53];out.arr[3][4][46]=s.arr[3][4][54];out.arr[3][4][47]=s.arr[3][4][55];out.arr[3][4][48]=s.arr[3][4][56];out.arr[3][4][49]=s.arr[3][4][57];out.arr[3][4][50]=s.arr[3][4][58];out.arr[3][4][51]=s.arr[3][4][59];out.arr[3][4][52]=s.arr[3][4][60];out.arr[3][4][53]=s.arr[3][4][61];
out.arr[3][4][54]=s.arr[3][4][62];out.arr[3][4][55]=s.arr[3][4][63];out.arr[3][4][56]=s.arr[3][4][0];out.arr[3][4][57]=s.arr[3][4][1];out.arr[3][4][58]=s.arr[3][4][2];out.arr[3][4][59]=s.arr[3][4][3];out.arr[3][4][60]=s.arr[3][4][4];out.arr[3][4][61]=s.arr[3][4][5];out.arr[3][4][62]=s.arr[3][4][6];out.arr[3][4][63]=s.arr[3][4][7];
out.arr[4][3][0]=s.arr[4][3][56];out.arr[4][3][1]=s.arr[4][3][57];out.arr[4][3][2]=s.arr[4][3][58];out.arr[4][3][3]=s.arr[4][3][59];out.arr[4][3][4]=s.arr[4][3][60];out.arr[4][3][5]=s.arr[4][3][61];out.arr[4][3][6]=s.arr[4][3][62];out.arr[4][3][7]=s.arr[4][3][63];out.arr[4][3][8]=s.arr[4][3][0];out.arr[4][3][9]=s.arr[4][3][1];
out.arr[4][3][10]=s.arr[4][3][2];out.arr[4][3][11]=s.arr[4][3][3];out.arr[4][3][12]=s.arr[4][3][4];out.arr[4][3][13]=s.arr[4][3][5];out.arr[4][3][14]=s.arr[4][3][6];out.arr[4][3][15]=s.arr[4][3][7];out.arr[4][3][16]=s.arr[4][3][8];out.arr[4][3][17]=s.arr[4][3][9];out.arr[4][3][18]=s.arr[4][3][10];out.arr[4][3][19]=s.arr[4][3][11];
out.arr[4][3][20]=s.arr[4][3][12];out.arr[4][3][21]=s.arr[4][3][13];out.arr[4][3][22]=s.arr[4][3][14];out.arr[4][3][23]=s.arr[4][3][15];out.arr[4][3][24]=s.arr[4][3][16];out.arr[4][3][25]=s.arr[4][3][17];out.arr[4][3][26]=s.arr[4][3][18];out.arr[4][3][27]=s.arr[4][3][19];out.arr[4][3][28]=s.arr[4][3][20];out.arr[4][3][29]=s.arr[4][3][21];
out.arr[4][3][30]=s.arr[4][3][22];out.arr[4][3][31]=s.arr[4][3][23];out.arr[4][3][32]=s.arr[4][3][24];out.arr[4][3][33]=s.arr[4][3][25];out.arr[4][3][34]=s.arr[4][3][26];out.arr[4][3][35]=s.arr[4][3][27];out.arr[4][3][36]=s.arr[4][3][28];out.arr[4][3][37]=s.arr[4][3][29];out.arr[4][3][38]=s.arr[4][3][30];out.arr[4][3][39]=s.arr[4][3][31];
out.arr[4][3][40]=s.arr[4][3][32];out.arr[4][3][41]=s.arr[4][3][33];out.arr[4][3][42]=s.arr[4][3][34];out.arr[4][3][43]=s.arr[4][3][35];out.arr[4][3][44]=s.arr[4][3][36];out.arr[4][3][45]=s.arr[4][3][37];out.arr[4][3][46]=s.arr[4][3][38];out.arr[4][3][47]=s.arr[4][3][39];out.arr[4][3][48]=s.arr[4][3][40];out.arr[4][3][49]=s.arr[4][3][41];
out.arr[4][3][50]=s.arr[4][3][42];out.arr[4][3][51]=s.arr[4][3][43];out.arr[4][3][52]=s.arr[4][3][44];out.arr[4][3][53]=s.arr[4][3][45];out.arr[4][3][54]=s.arr[4][3][46];out.arr[4][3][55]=s.arr[4][3][47];out.arr[4][3][56]=s.arr[4][3][48];out.arr[4][3][57]=s.arr[4][3][49];out.arr[4][3][58]=s.arr[4][3][50];out.arr[4][3][59]=s.arr[4][3][51];
out.arr[4][3][60]=s.arr[4][3][52];out.arr[4][3][61]=s.arr[4][3][53];out.arr[4][3][62]=s.arr[4][3][54];out.arr[4][3][63]=s.arr[4][3][55];out.arr[3][2][0]=s.arr[3][2][39];out.arr[3][2][1]=s.arr[3][2][40];out.arr[3][2][2]=s.arr[3][2][41];out.arr[3][2][3]=s.arr[3][2][42];out.arr[3][2][4]=s.arr[3][2][43];out.arr[3][2][5]=s.arr[3][2][44];
out.arr[3][2][6]=s.arr[3][2][45];out.arr[3][2][7]=s.arr[3][2][46];out.arr[3][2][8]=s.arr[3][2][47];out.arr[3][2][9]=s.arr[3][2][48];out.arr[3][2][10]=s.arr[3][2][49];out.arr[3][2][11]=s.arr[3][2][50];out.arr[3][2][12]=s.arr[3][2][51];out.arr[3][2][13]=s.arr[3][2][52];out.arr[3][2][14]=s.arr[3][2][53];out.arr[3][2][15]=s.arr[3][2][54];
out.arr[3][2][16]=s.arr[3][2][55];out.arr[3][2][17]=s.arr[3][2][56];out.arr[3][2][18]=s.arr[3][2][57];out.arr[3][2][19]=s.arr[3][2][58];out.arr[3][2][20]=s.arr[3][2][59];out.arr[3][2][21]=s.arr[3][2][60];out.arr[3][2][22]=s.arr[3][2][61];out.arr[3][2][23]=s.arr[3][2][62];out.arr[3][2][24]=s.arr[3][2][63];out.arr[3][2][25]=s.arr[3][2][0];
out.arr[3][2][26]=s.arr[3][2][1];out.arr[3][2][27]=s.arr[3][2][2];out.arr[3][2][28]=s.arr[3][2][3];out.arr[3][2][29]=s.arr[3][2][4];out.arr[3][2][30]=s.arr[3][2][5];out.arr[3][2][31]=s.arr[3][2][6];out.arr[3][2][32]=s.arr[3][2][7];out.arr[3][2][33]=s.arr[3][2][8];out.arr[3][2][34]=s.arr[3][2][9];out.arr[3][2][35]=s.arr[3][2][10];
out.arr[3][2][36]=s.arr[3][2][11];out.arr[3][2][37]=s.arr[3][2][12];out.arr[3][2][38]=s.arr[3][2][13];out.arr[3][2][39]=s.arr[3][2][14];out.arr[3][2][40]=s.arr[3][2][15];out.arr[3][2][41]=s.arr[3][2][16];out.arr[3][2][42]=s.arr[3][2][17];out.arr[3][2][43]=s.arr[3][2][18];out.arr[3][2][44]=s.arr[3][2][19];out.arr[3][2][45]=s.arr[3][2][20];
out.arr[3][2][46]=s.arr[3][2][21];out.arr[3][2][47]=s.arr[3][2][22];out.arr[3][2][48]=s.arr[3][2][23];out.arr[3][2][49]=s.arr[3][2][24];out.arr[3][2][50]=s.arr[3][2][25];out.arr[3][2][51]=s.arr[3][2][26];out.arr[3][2][52]=s.arr[3][2][27];out.arr[3][2][53]=s.arr[3][2][28];out.arr[3][2][54]=s.arr[3][2][29];out.arr[3][2][55]=s.arr[3][2][30];
out.arr[3][2][56]=s.arr[3][2][31];out.arr[3][2][57]=s.arr[3][2][32];out.arr[3][2][58]=s.arr[3][2][33];out.arr[3][2][59]=s.arr[3][2][34];out.arr[3][2][60]=s.arr[3][2][35];out.arr[3][2][61]=s.arr[3][2][36];out.arr[3][2][62]=s.arr[3][2][37];out.arr[3][2][63]=s.arr[3][2][38];out.arr[2][2][0]=s.arr[2][2][21];out.arr[2][2][1]=s.arr[2][2][22];
out.arr[2][2][2]=s.arr[2][2][23];out.arr[2][2][3]=s.arr[2][2][24];out.arr[2][2][4]=s.arr[2][2][25];out.arr[2][2][5]=s.arr[2][2][26];out.arr[2][2][6]=s.arr[2][2][27];out.arr[2][2][7]=s.arr[2][2][28];out.arr[2][2][8]=s.arr[2][2][29];out.arr[2][2][9]=s.arr[2][2][30];out.arr[2][2][10]=s.arr[2][2][31];out.arr[2][2][11]=s.arr[2][2][32];
out.arr[2][2][12]=s.arr[2][2][33];out.arr[2][2][13]=s.arr[2][2][34];out.arr[2][2][14]=s.arr[2][2][35];out.arr[2][2][15]=s.arr[2][2][36];out.arr[2][2][16]=s.arr[2][2][37];out.arr[2][2][17]=s.arr[2][2][38];out.arr[2][2][18]=s.arr[2][2][39];out.arr[2][2][19]=s.arr[2][2][40];out.arr[2][2][20]=s.arr[2][2][41];out.arr[2][2][21]=s.arr[2][2][42];
out.arr[2][2][22]=s.arr[2][2][43];out.arr[2][2][23]=s.arr[2][2][44];out.arr[2][2][24]=s.arr[2][2][45];out.arr[2][2][25]=s.arr[2][2][46];out.arr[2][2][26]=s.arr[2][2][47];out.arr[2][2][27]=s.arr[2][2][48];out.arr[2][2][28]=s.arr[2][2][49];out.arr[2][2][29]=s.arr[2][2][50];out.arr[2][2][30]=s.arr[2][2][51];out.arr[2][2][31]=s.arr[2][2][52];
out.arr[2][2][32]=s.arr[2][2][53];out.arr[2][2][33]=s.arr[2][2][54];out.arr[2][2][34]=s.arr[2][2][55];out.arr[2][2][35]=s.arr[2][2][56];out.arr[2][2][36]=s.arr[2][2][57];out.arr[2][2][37]=s.arr[2][2][58];out.arr[2][2][38]=s.arr[2][2][59];out.arr[2][2][39]=s.arr[2][2][60];out.arr[2][2][40]=s.arr[2][2][61];out.arr[2][2][41]=s.arr[2][2][62];
out.arr[2][2][42]=s.arr[2][2][63];out.arr[2][2][43]=s.arr[2][2][0];out.arr[2][2][44]=s.arr[2][2][1];out.arr[2][2][45]=s.arr[2][2][2];out.arr[2][2][46]=s.arr[2][2][3];out.arr[2][2][47]=s.arr[2][2][4];out.arr[2][2][48]=s.arr[2][2][5];out.arr[2][2][49]=s.arr[2][2][6];out.arr[2][2][50]=s.arr[2][2][7];out.arr[2][2][51]=s.arr[2][2][8];
out.arr[2][2][52]=s.arr[2][2][9];out.arr[2][2][53]=s.arr[2][2][10];out.arr[2][2][54]=s.arr[2][2][11];out.arr[2][2][55]=s.arr[2][2][12];out.arr[2][2][56]=s.arr[2][2][13];out.arr[2][2][57]=s.arr[2][2][14];out.arr[2][2][58]=s.arr[2][2][15];out.arr[2][2][59]=s.arr[2][2][16];out.arr[2][2][60]=s.arr[2][2][17];out.arr[2][2][61]=s.arr[2][2][18];
out.arr[2][2][62]=s.arr[2][2][19];out.arr[2][2][63]=s.arr[2][2][20];out.arr[2][0][0]=s.arr[2][0][2];out.arr[2][0][1]=s.arr[2][0][3];out.arr[2][0][2]=s.arr[2][0][4];out.arr[2][0][3]=s.arr[2][0][5];out.arr[2][0][4]=s.arr[2][0][6];out.arr[2][0][5]=s.arr[2][0][7];out.arr[2][0][6]=s.arr[2][0][8];out.arr[2][0][7]=s.arr[2][0][9];
out.arr[2][0][8]=s.arr[2][0][10];out.arr[2][0][9]=s.arr[2][0][11];out.arr[2][0][10]=s.arr[2][0][12];out.arr[2][0][11]=s.arr[2][0][13];out.arr[2][0][12]=s.arr[2][0][14];out.arr[2][0][13]=s.arr[2][0][15];out.arr[2][0][14]=s.arr[2][0][16];out.arr[2][0][15]=s.arr[2][0][17];out.arr[2][0][16]=s.arr[2][0][18];out.arr[2][0][17]=s.arr[2][0][19];
out.arr[2][0][18]=s.arr[2][0][20];out.arr[2][0][19]=s.arr[2][0][21];out.arr[2][0][20]=s.arr[2][0][22];out.arr[2][0][21]=s.arr[2][0][23];out.arr[2][0][22]=s.arr[2][0][24];out.arr[2][0][23]=s.arr[2][0][25];out.arr[2][0][24]=s.arr[2][0][26];out.arr[2][0][25]=s.arr[2][0][27];out.arr[2][0][26]=s.arr[2][0][28];out.arr[2][0][27]=s.arr[2][0][29];
out.arr[2][0][28]=s.arr[2][0][30];out.arr[2][0][29]=s.arr[2][0][31];out.arr[2][0][30]=s.arr[2][0][32];out.arr[2][0][31]=s.arr[2][0][33];out.arr[2][0][32]=s.arr[2][0][34];out.arr[2][0][33]=s.arr[2][0][35];out.arr[2][0][34]=s.arr[2][0][36];out.arr[2][0][35]=s.arr[2][0][37];out.arr[2][0][36]=s.arr[2][0][38];out.arr[2][0][37]=s.arr[2][0][39];
out.arr[2][0][38]=s.arr[2][0][40];out.arr[2][0][39]=s.arr[2][0][41];out.arr[2][0][40]=s.arr[2][0][42];out.arr[2][0][41]=s.arr[2][0][43];out.arr[2][0][42]=s.arr[2][0][44];out.arr[2][0][43]=s.arr[2][0][45];out.arr[2][0][44]=s.arr[2][0][46];out.arr[2][0][45]=s.arr[2][0][47];out.arr[2][0][46]=s.arr[2][0][48];out.arr[2][0][47]=s.arr[2][0][49];
out.arr[2][0][48]=s.arr[2][0][50];out.arr[2][0][49]=s.arr[2][0][51];out.arr[2][0][50]=s.arr[2][0][52];out.arr[2][0][51]=s.arr[2][0][53];out.arr[2][0][52]=s.arr[2][0][54];out.arr[2][0][53]=s.arr[2][0][55];out.arr[2][0][54]=s.arr[2][0][56];out.arr[2][0][55]=s.arr[2][0][57];out.arr[2][0][56]=s.arr[2][0][58];out.arr[2][0][57]=s.arr[2][0][59];
out.arr[2][0][58]=s.arr[2][0][60];out.arr[2][0][59]=s.arr[2][0][61];out.arr[2][0][60]=s.arr[2][0][62];out.arr[2][0][61]=s.arr[2][0][63];out.arr[2][0][62]=s.arr[2][0][0];out.arr[2][0][63]=s.arr[2][0][1];out.arr[0][4][0]=s.arr[0][4][46];out.arr[0][4][1]=s.arr[0][4][47];out.arr[0][4][2]=s.arr[0][4][48];out.arr[0][4][3]=s.arr[0][4][49];
out.arr[0][4][4]=s.arr[0][4][50];out.arr[0][4][5]=s.arr[0][4][51];out.arr[0][4][6]=s.arr[0][4][52];out.arr[0][4][7]=s.arr[0][4][53];out.arr[0][4][8]=s.arr[0][4][54];out.arr[0][4][9]=s.arr[0][4][55];out.arr[0][4][10]=s.arr[0][4][56];out.arr[0][4][11]=s.arr[0][4][57];out.arr[0][4][12]=s.arr[0][4][58];out.arr[0][4][13]=s.arr[0][4][59];
out.arr[0][4][14]=s.arr[0][4][60];out.arr[0][4][15]=s.arr[0][4][61];out.arr[0][4][16]=s.arr[0][4][62];out.arr[0][4][17]=s.arr[0][4][63];out.arr[0][4][18]=s.arr[0][4][0];out.arr[0][4][19]=s.arr[0][4][1];out.arr[0][4][20]=s.arr[0][4][2];out.arr[0][4][21]=s.arr[0][4][3];out.arr[0][4][22]=s.arr[0][4][4];out.arr[0][4][23]=s.arr[0][4][5];
out.arr[0][4][24]=s.arr[0][4][6];out.arr[0][4][25]=s.arr[0][4][7];out.arr[0][4][26]=s.arr[0][4][8];out.arr[0][4][27]=s.arr[0][4][9];out.arr[0][4][28]=s.arr[0][4][10];out.arr[0][4][29]=s.arr[0][4][11];out.arr[0][4][30]=s.arr[0][4][12];out.arr[0][4][31]=s.arr[0][4][13];out.arr[0][4][32]=s.arr[0][4][14];out.arr[0][4][33]=s.arr[0][4][15];
out.arr[0][4][34]=s.arr[0][4][16];out.arr[0][4][35]=s.arr[0][4][17];out.arr[0][4][36]=s.arr[0][4][18];out.arr[0][4][37]=s.arr[0][4][19];out.arr[0][4][38]=s.arr[0][4][20];out.arr[0][4][39]=s.arr[0][4][21];out.arr[0][4][40]=s.arr[0][4][22];out.arr[0][4][41]=s.arr[0][4][23];out.arr[0][4][42]=s.arr[0][4][24];out.arr[0][4][43]=s.arr[0][4][25];
out.arr[0][4][44]=s.arr[0][4][26];out.arr[0][4][45]=s.arr[0][4][27];out.arr[0][4][46]=s.arr[0][4][28];out.arr[0][4][47]=s.arr[0][4][29];out.arr[0][4][48]=s.arr[0][4][30];out.arr[0][4][49]=s.arr[0][4][31];out.arr[0][4][50]=s.arr[0][4][32];out.arr[0][4][51]=s.arr[0][4][33];out.arr[0][4][52]=s.arr[0][4][34];out.arr[0][4][53]=s.arr[0][4][35];
out.arr[0][4][54]=s.arr[0][4][36];out.arr[0][4][55]=s.arr[0][4][37];out.arr[0][4][56]=s.arr[0][4][38];out.arr[0][4][57]=s.arr[0][4][39];out.arr[0][4][58]=s.arr[0][4][40];out.arr[0][4][59]=s.arr[0][4][41];out.arr[0][4][60]=s.arr[0][4][42];out.arr[0][4][61]=s.arr[0][4][43];out.arr[0][4][62]=s.arr[0][4][44];out.arr[0][4][63]=s.arr[0][4][45];
out.arr[4][2][0]=s.arr[4][2][25];out.arr[4][2][1]=s.arr[4][2][26];out.arr[4][2][2]=s.arr[4][2][27];out.arr[4][2][3]=s.arr[4][2][28];out.arr[4][2][4]=s.arr[4][2][29];out.arr[4][2][5]=s.arr[4][2][30];out.arr[4][2][6]=s.arr[4][2][31];out.arr[4][2][7]=s.arr[4][2][32];out.arr[4][2][8]=s.arr[4][2][33];out.arr[4][2][9]=s.arr[4][2][34];
out.arr[4][2][10]=s.arr[4][2][35];out.arr[4][2][11]=s.arr[4][2][36];out.arr[4][2][12]=s.arr[4][2][37];out.arr[4][2][13]=s.arr[4][2][38];out.arr[4][2][14]=s.arr[4][2][39];out.arr[4][2][15]=s.arr[4][2][40];out.arr[4][2][16]=s.arr[4][2][41];out.arr[4][2][17]=s.arr[4][2][42];out.arr[4][2][18]=s.arr[4][2][43];out.arr[4][2][19]=s.arr[4][2][44];
out.arr[4][2][20]=s.arr[4][2][45];out.arr[4][2][21]=s.arr[4][2][46];out.arr[4][2][22]=s.arr[4][2][47];out.arr[4][2][23]=s.arr[4][2][48];out.arr[4][2][24]=s.arr[4][2][49];out.arr[4][2][25]=s.arr[4][2][50];out.arr[4][2][26]=s.arr[4][2][51];out.arr[4][2][27]=s.arr[4][2][52];out.arr[4][2][28]=s.arr[4][2][53];out.arr[4][2][29]=s.arr[4][2][54];
out.arr[4][2][30]=s.arr[4][2][55];out.arr[4][2][31]=s.arr[4][2][56];out.arr[4][2][32]=s.arr[4][2][57];out.arr[4][2][33]=s.arr[4][2][58];out.arr[4][2][34]=s.arr[4][2][59];out.arr[4][2][35]=s.arr[4][2][60];out.arr[4][2][36]=s.arr[4][2][61];out.arr[4][2][37]=s.arr[4][2][62];out.arr[4][2][38]=s.arr[4][2][63];out.arr[4][2][39]=s.arr[4][2][0];
out.arr[4][2][40]=s.arr[4][2][1];out.arr[4][2][41]=s.arr[4][2][2];out.arr[4][2][42]=s.arr[4][2][3];out.arr[4][2][43]=s.arr[4][2][4];out.arr[4][2][44]=s.arr[4][2][5];out.arr[4][2][45]=s.arr[4][2][6];out.arr[4][2][46]=s.arr[4][2][7];out.arr[4][2][47]=s.arr[4][2][8];out.arr[4][2][48]=s.arr[4][2][9];out.arr[4][2][49]=s.arr[4][2][10];
out.arr[4][2][50]=s.arr[4][2][11];out.arr[4][2][51]=s.arr[4][2][12];out.arr[4][2][52]=s.arr[4][2][13];out.arr[4][2][53]=s.arr[4][2][14];out.arr[4][2][54]=s.arr[4][2][15];out.arr[4][2][55]=s.arr[4][2][16];out.arr[4][2][56]=s.arr[4][2][17];out.arr[4][2][57]=s.arr[4][2][18];out.arr[4][2][58]=s.arr[4][2][19];out.arr[4][2][59]=s.arr[4][2][20];
out.arr[4][2][60]=s.arr[4][2][21];out.arr[4][2][61]=s.arr[4][2][22];out.arr[4][2][62]=s.arr[4][2][23];out.arr[4][2][63]=s.arr[4][2][24];out.arr[2][4][0]=s.arr[2][4][3];out.arr[2][4][1]=s.arr[2][4][4];out.arr[2][4][2]=s.arr[2][4][5];out.arr[2][4][3]=s.arr[2][4][6];out.arr[2][4][4]=s.arr[2][4][7];out.arr[2][4][5]=s.arr[2][4][8];
out.arr[2][4][6]=s.arr[2][4][9];out.arr[2][4][7]=s.arr[2][4][10];out.arr[2][4][8]=s.arr[2][4][11];out.arr[2][4][9]=s.arr[2][4][12];out.arr[2][4][10]=s.arr[2][4][13];out.arr[2][4][11]=s.arr[2][4][14];out.arr[2][4][12]=s.arr[2][4][15];out.arr[2][4][13]=s.arr[2][4][16];out.arr[2][4][14]=s.arr[2][4][17];out.arr[2][4][15]=s.arr[2][4][18];
out.arr[2][4][16]=s.arr[2][4][19];out.arr[2][4][17]=s.arr[2][4][20];out.arr[2][4][18]=s.arr[2][4][21];out.arr[2][4][19]=s.arr[2][4][22];out.arr[2][4][20]=s.arr[2][4][23];out.arr[2][4][21]=s.arr[2][4][24];out.arr[2][4][22]=s.arr[2][4][25];out.arr[2][4][23]=s.arr[2][4][26];out.arr[2][4][24]=s.arr[2][4][27];out.arr[2][4][25]=s.arr[2][4][28];
out.arr[2][4][26]=s.arr[2][4][29];out.arr[2][4][27]=s.arr[2][4][30];out.arr[2][4][28]=s.arr[2][4][31];out.arr[2][4][29]=s.arr[2][4][32];out.arr[2][4][30]=s.arr[2][4][33];out.arr[2][4][31]=s.arr[2][4][34];out.arr[2][4][32]=s.arr[2][4][35];out.arr[2][4][33]=s.arr[2][4][36];out.arr[2][4][34]=s.arr[2][4][37];out.arr[2][4][35]=s.arr[2][4][38];
out.arr[2][4][36]=s.arr[2][4][39];out.arr[2][4][37]=s.arr[2][4][40];out.arr[2][4][38]=s.arr[2][4][41];out.arr[2][4][39]=s.arr[2][4][42];out.arr[2][4][40]=s.arr[2][4][43];out.arr[2][4][41]=s.arr[2][4][44];out.arr[2][4][42]=s.arr[2][4][45];out.arr[2][4][43]=s.arr[2][4][46];out.arr[2][4][44]=s.arr[2][4][47];out.arr[2][4][45]=s.arr[2][4][48];
out.arr[2][4][46]=s.arr[2][4][49];out.arr[2][4][47]=s.arr[2][4][50];out.arr[2][4][48]=s.arr[2][4][51];out.arr[2][4][49]=s.arr[2][4][52];out.arr[2][4][50]=s.arr[2][4][53];out.arr[2][4][51]=s.arr[2][4][54];out.arr[2][4][52]=s.arr[2][4][55];out.arr[2][4][53]=s.arr[2][4][56];out.arr[2][4][54]=s.arr[2][4][57];out.arr[2][4][55]=s.arr[2][4][58];
out.arr[2][4][56]=s.arr[2][4][59];out.arr[2][4][57]=s.arr[2][4][60];out.arr[2][4][58]=s.arr[2][4][61];out.arr[2][4][59]=s.arr[2][4][62];out.arr[2][4][60]=s.arr[2][4][63];out.arr[2][4][61]=s.arr[2][4][0];out.arr[2][4][62]=s.arr[2][4][1];out.arr[2][4][63]=s.arr[2][4][2];out.arr[4][1][0]=s.arr[4][1][44];out.arr[4][1][1]=s.arr[4][1][45];
out.arr[4][1][2]=s.arr[4][1][46];out.arr[4][1][3]=s.arr[4][1][47];out.arr[4][1][4]=s.arr[4][1][48];out.arr[4][1][5]=s.arr[4][1][49];out.arr[4][1][6]=s.arr[4][1][50];out.arr[4][1][7]=s.arr[4][1][51];out.arr[4][1][8]=s.arr[4][1][52];out.arr[4][1][9]=s.arr[4][1][53];out.arr[4][1][10]=s.arr[4][1][54];out.arr[4][1][11]=s.arr[4][1][55];
out.arr[4][1][12]=s.arr[4][1][56];out.arr[4][1][13]=s.arr[4][1][57];out.arr[4][1][14]=s.arr[4][1][58];out.arr[4][1][15]=s.arr[4][1][59];out.arr[4][1][16]=s.arr[4][1][60];out.arr[4][1][17]=s.arr[4][1][61];out.arr[4][1][18]=s.arr[4][1][62];out.arr[4][1][19]=s.arr[4][1][63];out.arr[4][1][20]=s.arr[4][1][0];out.arr[4][1][21]=s.arr[4][1][1];
out.arr[4][1][22]=s.arr[4][1][2];out.arr[4][1][23]=s.arr[4][1][3];out.arr[4][1][24]=s.arr[4][1][4];out.arr[4][1][25]=s.arr[4][1][5];out.arr[4][1][26]=s.arr[4][1][6];out.arr[4][1][27]=s.arr[4][1][7];out.arr[4][1][28]=s.arr[4][1][8];out.arr[4][1][29]=s.arr[4][1][9];out.arr[4][1][30]=s.arr[4][1][10];out.arr[4][1][31]=s.arr[4][1][11];
out.arr[4][1][32]=s.arr[4][1][12];out.arr[4][1][33]=s.arr[4][1][13];out.arr[4][1][34]=s.arr[4][1][14];out.arr[4][1][35]=s.arr[4][1][15];out.arr[4][1][36]=s.arr[4][1][16];out.arr[4][1][37]=s.arr[4][1][17];out.arr[4][1][38]=s.arr[4][1][18];out.arr[4][1][39]=s.arr[4][1][19];out.arr[4][1][40]=s.arr[4][1][20];out.arr[4][1][41]=s.arr[4][1][21];
out.arr[4][1][42]=s.arr[4][1][22];out.arr[4][1][43]=s.arr[4][1][23];out.arr[4][1][44]=s.arr[4][1][24];out.arr[4][1][45]=s.arr[4][1][25];out.arr[4][1][46]=s.arr[4][1][26];out.arr[4][1][47]=s.arr[4][1][27];out.arr[4][1][48]=s.arr[4][1][28];out.arr[4][1][49]=s.arr[4][1][29];out.arr[4][1][50]=s.arr[4][1][30];out.arr[4][1][51]=s.arr[4][1][31];
out.arr[4][1][52]=s.arr[4][1][32];out.arr[4][1][53]=s.arr[4][1][33];out.arr[4][1][54]=s.arr[4][1][34];out.arr[4][1][55]=s.arr[4][1][35];out.arr[4][1][56]=s.arr[4][1][36];out.arr[4][1][57]=s.arr[4][1][37];out.arr[4][1][58]=s.arr[4][1][38];out.arr[4][1][59]=s.arr[4][1][39];out.arr[4][1][60]=s.arr[4][1][40];out.arr[4][1][61]=s.arr[4][1][41];
out.arr[4][1][62]=s.arr[4][1][42];out.arr[4][1][63]=s.arr[4][1][43];out.arr[1][1][0]=s.arr[1][1][20];out.arr[1][1][1]=s.arr[1][1][21];out.arr[1][1][2]=s.arr[1][1][22];out.arr[1][1][3]=s.arr[1][1][23];out.arr[1][1][4]=s.arr[1][1][24];out.arr[1][1][5]=s.arr[1][1][25];out.arr[1][1][6]=s.arr[1][1][26];out.arr[1][1][7]=s.arr[1][1][27];
out.arr[1][1][8]=s.arr[1][1][28];out.arr[1][1][9]=s.arr[1][1][29];out.arr[1][1][10]=s.arr[1][1][30];out.arr[1][1][11]=s.arr[1][1][31];out.arr[1][1][12]=s.arr[1][1][32];out.arr[1][1][13]=s.arr[1][1][33];out.arr[1][1][14]=s.arr[1][1][34];out.arr[1][1][15]=s.arr[1][1][35];out.arr[1][1][16]=s.arr[1][1][36];out.arr[1][1][17]=s.arr[1][1][37];
out.arr[1][1][18]=s.arr[1][1][38];out.arr[1][1][19]=s.arr[1][1][39];out.arr[1][1][20]=s.arr[1][1][40];out.arr[1][1][21]=s.arr[1][1][41];out.arr[1][1][22]=s.arr[1][1][42];out.arr[1][1][23]=s.arr[1][1][43];out.arr[1][1][24]=s.arr[1][1][44];out.arr[1][1][25]=s.arr[1][1][45];out.arr[1][1][26]=s.arr[1][1][46];out.arr[1][1][27]=s.arr[1][1][47];
out.arr[1][1][28]=s.arr[1][1][48];out.arr[1][1][29]=s.arr[1][1][49];out.arr[1][1][30]=s.arr[1][1][50];out.arr[1][1][31]=s.arr[1][1][51];out.arr[1][1][32]=s.arr[1][1][52];out.arr[1][1][33]=s.arr[1][1][53];out.arr[1][1][34]=s.arr[1][1][54];out.arr[1][1][35]=s.arr[1][1][55];out.arr[1][1][36]=s.arr[1][1][56];out.arr[1][1][37]=s.arr[1][1][57];
out.arr[1][1][38]=s.arr[1][1][58];out.arr[1][1][39]=s.arr[1][1][59];out.arr[1][1][40]=s.arr[1][1][60];out.arr[1][1][41]=s.arr[1][1][61];out.arr[1][1][42]=s.arr[1][1][62];out.arr[1][1][43]=s.arr[1][1][63];out.arr[1][1][44]=s.arr[1][1][0];out.arr[1][1][45]=s.arr[1][1][1];out.arr[1][1][46]=s.arr[1][1][2];out.arr[1][1][47]=s.arr[1][1][3];
out.arr[1][1][48]=s.arr[1][1][4];out.arr[1][1][49]=s.arr[1][1][5];out.arr[1][1][50]=s.arr[1][1][6];out.arr[1][1][51]=s.arr[1][1][7];out.arr[1][1][52]=s.arr[1][1][8];out.arr[1][1][53]=s.arr[1][1][9];out.arr[1][1][54]=s.arr[1][1][10];out.arr[1][1][55]=s.arr[1][1][11];out.arr[1][1][56]=s.arr[1][1][12];out.arr[1][1][57]=s.arr[1][1][13];
out.arr[1][1][58]=s.arr[1][1][14];out.arr[1][1][59]=s.arr[1][1][15];out.arr[1][1][60]=s.arr[1][1][16];out.arr[1][1][61]=s.arr[1][1][17];out.arr[1][1][62]=s.arr[1][1][18];out.arr[1][1][63]=s.arr[1][1][19];


        out
    }

    fn pi(s: StateArray) -> StateArray {
        // for y in 0..StateArray::Y_SIZE {
        //     for x in 0..StateArray::X_SIZE {
        //         let x_s = (x + 3 * y) % StateArray::X_SIZE;
        //         out[x][y] = s[x_s][x];
        //     }
        // }
        let mut out = s;
        out.arr[0][0] = s.arr[0][0];
        out.arr[0][1] = s.arr[3][0];
        out.arr[0][2] = s.arr[1][0];
        out.arr[0][3] = s.arr[4][0];
        out.arr[0][4] = s.arr[2][0];
        out.arr[1][0] = s.arr[1][1];
        out.arr[1][1] = s.arr[4][1];
        out.arr[1][2] = s.arr[2][1];
        out.arr[1][3] = s.arr[0][1];
        out.arr[1][4] = s.arr[3][1];
        out.arr[2][0] = s.arr[2][2];
        out.arr[2][1] = s.arr[0][2];
        out.arr[2][2] = s.arr[3][2];
        out.arr[2][3] = s.arr[1][2];
        out.arr[2][4] = s.arr[4][2];
        out.arr[3][0] = s.arr[3][3];
        out.arr[3][1] = s.arr[1][3];
        out.arr[3][2] = s.arr[4][3];
        out.arr[3][3] = s.arr[2][3];
        out.arr[3][4] = s.arr[0][3];
        out.arr[4][0] = s.arr[4][4];
        out.arr[4][1] = s.arr[2][4];
        out.arr[4][2] = s.arr[0][4];
        out.arr[4][3] = s.arr[3][4];
        out.arr[4][4] = s.arr[1][4];
        out
    }

    fn chi(s: StateArray) -> StateArray {
        let mut out = s;
        out.iter_mut()
            .zip(s.iter().cycle().skip(1).zip(s.iter().cycle().skip(2)))
            .for_each(|(a, (b, c))| {
                a.iter_mut()
                    .zip(b.iter().zip(c.iter()))
                    .for_each(|(a, (b, c))| {
                        let (a, b, c) = (
                            StateArray::as_u128_arr_mut(a),
                            StateArray::as_u128_arr(b),
                            StateArray::as_u128_arr(c),
                        );
                        a.iter_mut().zip(b.iter().zip(c)).for_each(|(a, (&b, &c))| {
                            *a ^= (b ^ 0x1010101010101010101010101010101u128) & c;
                        });
                    });
            });
        out
    }

    #[inline]
    fn rc(t: usize) -> u8 {
        const ARR: [u8; 256] = [
            1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1,
            1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1,
            1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1,
            1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0,
            1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1,
            1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1,
            1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1,
            1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1,
            0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1,
        ];
        ARR[t & 255]
    }

    fn iota(round_idx: usize, mut s: StateArray) -> StateArray {
        let mut rc = [0u8; StateArray::Z_SIZE];
        let l = s.lane_size().ilog2() as usize;
        for j in 0..=l {
            rc[(1 << j) - 1] = Self::rc(j + 7 * round_idx);
        }

        let (s_z, rc_z) = (
            StateArray::as_u128_arr_mut(&mut s.arr[0][0]),
            StateArray::cvt_u128_arr(rc),
        );
        s_z.iter_mut().zip(rc_z).for_each(|(a, b)| *a ^= b);
        s
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
