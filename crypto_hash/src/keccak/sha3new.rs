use std::ops::BitXorAssign;

#[rustfmt::skip]
macro_rules! unroll5 {
    ($var:ident, $body:block) => {
        { const $var: usize = 0; $body; }
        { const $var: usize = 1; $body; }
        { const $var: usize = 2; $body; }
        { const $var: usize = 3; $body; }
        { const $var: usize = 4; $body; }
    };
}

#[rustfmt::skip]
macro_rules! unroll24 {
    ($var: ident, $body: block) => {
        { const $var: usize = 0; $body; }
        { const $var: usize = 1; $body; }
        { const $var: usize = 2; $body; }
        { const $var: usize = 3; $body; }
        { const $var: usize = 4; $body; }
        { const $var: usize = 5; $body; }
        { const $var: usize = 6; $body; }
        { const $var: usize = 7; $body; }
        { const $var: usize = 8; $body; }
        { const $var: usize = 9; $body; }
        { const $var: usize = 10; $body; }
        { const $var: usize = 11; $body; }
        { const $var: usize = 12; $body; }
        { const $var: usize = 13; $body; }
        { const $var: usize = 14; $body; }
        { const $var: usize = 15; $body; }
        { const $var: usize = 16; $body; }
        { const $var: usize = 17; $body; }
        { const $var: usize = 18; $body; }
        { const $var: usize = 19; $body; }
        { const $var: usize = 20; $body; }
        { const $var: usize = 21; $body; }
        { const $var: usize = 22; $body; }
        { const $var: usize = 23; $body; }
    };
}

/// z0 z1 z2 z3  ... z63 | ...| z0 ... z63
///     x0         | ....  |         ... x4
///                        y0     ...          | ... | y4
/// (z,x,y) u64 * 5 * 5
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct StateArray(pub [u64; 25]);

impl StateArray {
    const RHO: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];

    const PI: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    #[rustfmt::skip]
    const RC: [u64; 24] = [
        0x0000000000000001,0x0000000000008082,0x800000000000808a,0x8000000080008000,0x000000000000808b,0x0000000080000001,
        0x8000000080008081,0x8000000000008009,0x000000000000008a,0x0000000000000088,0x0000000080008009,0x000000008000000a,
        0x000000008000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,
        0x000000000000800a,0x800000008000000a,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008,
    ];

    pub fn update(data: &[u8]) -> StateArray {
        let mut d = [0u64; 25];
        d.iter_mut().zip(data.chunks_exact(8)).for_each(|(a, b)| {
            *a = u64::from_le_bytes(b.try_into().unwrap());
        });

        Self(d)
    }

    pub fn cvt_to_str(&mut self, data: &mut Vec<u8>) {
        self.0
            .iter()
            .for_each(|x| data.extend_from_slice(&x.to_le_bytes()))
    }

    #[allow(unused_assignments)]
    pub fn permutation(&mut self, round_count: usize) {
        let state = &mut self.0;
        if round_count > 24 {
            panic!("A round_count greater than 24 is not supported!");
        }

        // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=25
        // "the rounds of KECCAK-p[b, nr] match the last rounds of KECCAK-f[b]"
        let round_consts = &Self::RC[(24 - round_count)..24];

        // not unrolling this loop results in a much smaller function, plus
        // it positively influences performance due to the smaller load on I-cache
        for &rc in round_consts {
            let mut array = [0u64; 5];

            // Theta
            unroll5!(X, {
                unroll5!(Y, {
                    array[X] ^= state[5 * Y + X];
                });
            });

            unroll5!(X, {
                unroll5!(Y, {
                    let t1 = array[(X + 4) % 5];
                    let t2 = array[(X + 1) % 5].rotate_left(1);
                    state[5 * Y + X] ^= t1 ^ t2;
                });
            });

            // Rho and pi
            let mut last = state[1];
            unroll24!(X, {
                array[0] = state[Self::PI[X]];
                state[Self::PI[X]] = last.rotate_left(Self::RHO[X]);
                last = array[0];
            });

            // Chi
            unroll5!(Y_STEP, {
                const Y: usize = 5 * Y_STEP;

                unroll5!(X, {
                    array[X] = state[Y + X];
                });

                unroll5!(X, {
                    let t1 = !array[(X + 1) % 5];
                    let t2 = array[(X + 2) % 5];
                    state[Y + X] = array[X] ^ (t1 & t2);
                });
            });

            // Iota
            state[0] ^= rc;
        }
    }
}

impl BitXorAssign for StateArray {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0.iter_mut().zip(rhs.0).for_each(|(a, b)| *a ^= b);
    }
}
