use crate::{CipherError, KDF};
use crypto_hash::{blake::BLAKE2b, DigestX};
use std::{io::Write, num::Wrapping};
use utils::Block;
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

use super::Params;

#[derive(Clone)]
pub struct Argon2 {
    params: Params,
    h0: Vec<u8>,
    // BLAKE2b-512
    blake2b: BLAKE2b,
}

impl Argon2 {
    /// `salt`: 长度推荐是16字节;
    pub fn new(
        mut password: Vec<u8>,
        mut salt: Vec<u8>,
        params: Params,
    ) -> Result<Self, CipherError> {
        if password.len() > (u32::MAX as usize) {
            Err(CipherError::Other(
                "argon2: password length need to less than 1<<32".to_string(),
            ))
        } else if salt.len() > (u32::MAX as usize) {
            Err(CipherError::Other(
                "argon: salt length need to less than 1<<32".to_string(),
            ))
        } else {
            let mut bb = BLAKE2b::new(64).unwrap();
            let push_data =
                |x: &mut BLAKE2b, y: u32| x.write_all(y.to_le_bytes().as_slice()).unwrap();

            push_data(&mut bb, params.degree_of_parallelism());
            push_data(&mut bb, params.tag_len());
            push_data(&mut bb, params.mem_size());
            push_data(&mut bb, params.num_of_passes());
            push_data(&mut bb, params.version());
            push_data(&mut bb, params.argon2_type());
            push_data(&mut bb, password.len() as u32);
            bb.write_all(password.as_slice()).unwrap();
            push_data(&mut bb, salt.len() as u32);
            bb.write_all(salt.as_slice()).unwrap();
            push_data(&mut bb, params.secret().len() as u32);
            bb.write_all(params.secret()).unwrap();
            push_data(&mut bb, params.associated_data().len() as u32);
            bb.write_all(params.associated_data()).unwrap();
            let h0 = bb.finish_x();

            #[cfg(feature = "sec-zeroize")]
            {
                password.zeroize();
                salt.zeroize();
            }

            Ok(Self {
                params,
                blake2b: bb,
                h0,
            })
        }
    }

    fn tag_len(&self) -> u32 {
        self.params.tag_len()
    }

    fn p(&self) -> u32 {
        self.params.degree_of_parallelism()
    }

    fn m(&self) -> u32 {
        self.params.mem_size()
    }

    // m'
    fn m_(&self) -> u32 {
        4 * self.p() * (self.m() / (4 * self.p()))
    }

    fn q(&self) -> u32 {
        self.m_() / self.p()
    }

    fn t(&self) -> u32 {
        self.params.num_of_passes()
    }

    /// Chapter 3.3 variable length hash function
    fn var_len_hash(blake2b: &mut BLAKE2b, msgs: &[&[u8]], len: u32) -> Vec<u8> {
        if len < 64 {
            let mut blake2b = BLAKE2b::new(len as u8).unwrap();
            Self::var_len_hash_(&mut blake2b, msgs, len)
        } else {
            Self::var_len_hash_(blake2b, msgs, len)
        }
    }

    fn var_len_hash_(blake2b: &mut BLAKE2b, msgs: &[&[u8]], len: u32) -> Vec<u8> {
        blake2b.reset_x();
        blake2b.write_all(len.to_le_bytes().as_slice()).unwrap();
        for msg in msgs {
            blake2b.write_all(msg).unwrap();
        }
        if len <= 64 {
            let mut out = blake2b.finish_x();
            out.truncate(len as usize);
            out
        } else {
            let r = ((len + 31) / 32) - 2;
            let mut out = Vec::with_capacity(32 * r as usize + 32);
            let mut vi = blake2b.finish_x();
            out.extend_from_slice(&vi[..32]);
            for _ in 2..=r {
                vi = blake2b.digest(vi.as_slice());
                out.extend_from_slice(&vi[..32]);
            }

            let len = len - 32 * r;
            let mut blake2b = BLAKE2b::new(len as u8).unwrap();
            vi = blake2b.digest(vi.as_slice());
            out.append(&mut vi);

            out
        }
    }

    // Chapter 3.2 Argon2 operation
    // Chapter 3.4 Indexing
    fn generate_block(&mut self) -> Vec<[u64; 128]> {
        let (p, q) = (self.p() as usize, self.q() as usize);
        let mut b = vec![[0u64; 128]; p * q];

        for (i, lane) in b.chunks_exact_mut(q).enumerate() {
            for (j, block) in lane.iter_mut().take(2).enumerate() {
                let h = Self::var_len_hash(
                    &mut self.blake2b,
                    &[
                        self.h0.as_slice(),
                        (j as u32).to_le_bytes().as_slice(),
                        (i as u32).to_le_bytes().as_slice(),
                    ],
                    1024,
                );

                block.iter_mut().zip(h.chunks_exact(8)).for_each(|(a, b)| {
                    *a = u64::from_le_bytes(Block::to_arr_uncheck(b));
                });
            }
        }

        let (iterations, slices, lanes) = (self.t() as u64, 4, self.p() as u64);
        for pass_idx in 0..iterations {
            for slice_idx in 0..slices {
                for lane_idx in 0..lanes {
                    self.process_segment(&mut b, pass_idx, slice_idx, lane_idx);
                }
            }
        }

        b
    }

    fn process_segment(
        &mut self,
        b: &mut [[u64; 128]],
        pass_idx: u64,
        slice_idx: u64,
        lane_idx: u64,
    ) {
        let (mut in_b, mut addr_b, zero) = ([0u64; 128], [0u64; 128], [0u64; 128]);
        let (m_, iterations, mode, lane_len) = (
            self.m_(),
            self.t(),
            self.params.argon2_type(),
            self.q() as u64,
        );
        let segment_len = lane_len / 4;

        let is_indepent_addr = self.params.is_argon2i()
            || (self.params.is_argon2id() && pass_idx == 0 && slice_idx < 2);
        if is_indepent_addr {
            in_b[0] = pass_idx.to_le();
            in_b[1] = lane_idx.to_le();
            in_b[2] = slice_idx.to_le();
            in_b[3] = (m_ as u64).to_le();
            in_b[4] = (iterations as u64).to_le();
            in_b[5] = (mode as u64).to_le();
        }

        let mut idx = if pass_idx == 0 && slice_idx == 0 {
            if self.params.is_argon2i() || self.params.is_argon2id() {
                Self::update_indexing_block(&zero, &mut in_b, &mut addr_b);
            }
            2
        } else {
            0
        };

        let mut offset = (lane_idx * lane_len + slice_idx * segment_len + idx) as usize;
        while idx < segment_len {
            let mut prev_idx = offset.wrapping_sub(1);
            if idx == 0 && slice_idx == 0 {
                // last block in lane
                prev_idx = prev_idx.wrapping_add(lane_len as usize);
            }

            let rand_idx = if is_indepent_addr {
                if idx % 128 == 0 {
                    Self::update_indexing_block(&zero, &mut in_b, &mut addr_b);
                }
                addr_b[(idx % 128) as usize]
            } else {
                b[prev_idx][0]
            };

            let new_offset =
                self.index_alpha(pass_idx, slice_idx, lane_idx, idx, rand_idx) as usize;
            let nblock = Self::compress(&b[prev_idx], &b[new_offset]);
            b[offset].iter_mut().zip(nblock).for_each(|(a, b)| *a ^= b);
            offset += 1;
            idx += 1;
        }
    }

    fn index_alpha(
        &mut self,
        pass_idx: u64,
        slice_idx: u64,
        lane_idx: u64,
        idx: u64,
        rand: u64,
    ) -> u64 {
        let (lane_len, lanes) = (self.q() as u64, self.p() as u64);
        let segment_len = lane_len / 4;

        let ref_lane = if pass_idx == 0 && slice_idx == 0 {
            lane_idx
        } else {
            (rand >> 32) % lanes
        };

        let (mut m, mut s) = (3 * segment_len, ((slice_idx + 1) % 4) * segment_len);
        if lane_idx == ref_lane {
            m += idx;
        }
        if pass_idx == 0 {
            m = slice_idx * segment_len;
            s = 0;
            if slice_idx == 0 || lane_idx == ref_lane {
                m += idx;
            }
        }
        if idx == 0 || lane_idx == ref_lane {
            m -= 1;
        }

        // phi
        let p = rand & 0xFFFFFFFF;
        let p = (p * p) >> 32;
        let p = (p * m) >> 32;

        ref_lane * lane_len + (s + m - p - 1) % lane_len
    }

    fn update_indexing_block(
        zero_block: &[u64; 128],
        input_block: &mut [u64; 128],
        indexing_block: &mut [u64; 128],
    ) {
        // counter
        input_block[6] += 1;
        *indexing_block = Self::compress(zero_block, input_block);
        *indexing_block = Self::compress(zero_block, indexing_block);
    }

    // Chapter 3.5
    // 调用者保证x,y各是128个字
    fn compress(x: &[u64; 128], y: &[u64; 128]) -> [u64; 128] {
        let mut r = [0u64; 128];
        r.iter_mut()
            .zip(x.iter().zip(y.iter()))
            .for_each(|(a, (&b, &c))| *a = b ^ c);

        const X: u64 = u32::MAX as u64;
        macro_rules! GB {
            ($a: expr, $b: expr, $c: expr, $d: expr) => {
                $a = (Wrapping($a)
                    + Wrapping($b)
                    + Wrapping(2) * Wrapping(X & $a) * Wrapping(X & $b))
                .0;
                $d = ($d ^ $a).rotate_right(32);
                $c = (Wrapping($c)
                    + Wrapping($d)
                    + Wrapping(2) * Wrapping(X & $c) * Wrapping(X & $d))
                .0;
                $b = ($b ^ $c).rotate_right(24);
                $a = (Wrapping($a)
                    + Wrapping($b)
                    + Wrapping(2) * Wrapping(X & $a) * Wrapping(X & $b))
                .0;
                $d = ($d ^ $a).rotate_right(16);
                $c = (Wrapping($c)
                    + Wrapping($d)
                    + Wrapping(2) * Wrapping(X & $c) * Wrapping(X & $d))
                .0;
                $b = ($b ^ $c).rotate_right(63);
            };
        }

        macro_rules! P {
            ($v_0: expr, $v_1: expr, $v_2: expr, $v_3: expr, $v_4: expr, $v_5: expr, $v_6: expr, $v_7: expr, $v_8: expr, $v_9: expr, $v_10: expr, $v_11: expr, $v_12: expr, $v_13: expr, $v_14: expr, $v_15: expr) => {
                GB!($v_0, $v_4, $v_8, $v_12);
                GB!($v_1, $v_5, $v_9, $v_13);
                GB!($v_2, $v_6, $v_10, $v_14);
                GB!($v_3, $v_7, $v_11, $v_15);
                GB!($v_0, $v_5, $v_10, $v_15);
                GB!($v_1, $v_6, $v_11, $v_12);
                GB!($v_2, $v_7, $v_8, $v_13);
                GB!($v_3, $v_4, $v_9, $v_14);
            };
        }

        // P!(r[], r[], r[], r[], r[], r[], r[], r[], r[], r[], r[], r[], r[], r[],r[], r[]);
        // P rowwise
        P!(
            r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13],
            r[14], r[15]
        );
        P!(
            r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23], r[24], r[25], r[26], r[27],
            r[28], r[29], r[30], r[31]
        );
        P!(
            r[32], r[33], r[34], r[35], r[36], r[37], r[38], r[39], r[40], r[41], r[42], r[43],
            r[44], r[45], r[46], r[47]
        );
        P!(
            r[48], r[49], r[50], r[51], r[52], r[53], r[54], r[55], r[56], r[57], r[58], r[59],
            r[60], r[61], r[62], r[63]
        );
        P!(
            r[64], r[65], r[66], r[67], r[68], r[69], r[70], r[71], r[72], r[73], r[74], r[75],
            r[76], r[77], r[78], r[79]
        );
        P!(
            r[80], r[81], r[82], r[83], r[84], r[85], r[86], r[87], r[88], r[89], r[90], r[91],
            r[92], r[93], r[94], r[95]
        );
        P!(
            r[96], r[97], r[98], r[99], r[100], r[101], r[102], r[103], r[104], r[105], r[106],
            r[107], r[108], r[109], r[110], r[111]
        );
        P!(
            r[112], r[113], r[114], r[115], r[116], r[117], r[118], r[119], r[120], r[121], r[122],
            r[123], r[124], r[125], r[126], r[127]
        );

        // P columnwise
        P!(
            r[0], r[1], r[16], r[17], r[32], r[33], r[48], r[49], r[64], r[65], r[80], r[81],
            r[96], r[97], r[112], r[113]
        );
        P!(
            r[2], r[3], r[18], r[19], r[34], r[35], r[50], r[51], r[66], r[67], r[82], r[83],
            r[98], r[99], r[114], r[115]
        );
        P!(
            r[4], r[5], r[20], r[21], r[36], r[37], r[52], r[53], r[68], r[69], r[84], r[85],
            r[100], r[101], r[116], r[117]
        );
        P!(
            r[6], r[7], r[22], r[23], r[38], r[39], r[54], r[55], r[70], r[71], r[86], r[87],
            r[102], r[103], r[118], r[119]
        );
        P!(
            r[8], r[9], r[24], r[25], r[40], r[41], r[56], r[57], r[72], r[73], r[88], r[89],
            r[104], r[105], r[120], r[121]
        );
        P!(
            r[10], r[11], r[26], r[27], r[42], r[43], r[58], r[59], r[74], r[75], r[90], r[91],
            r[106], r[107], r[122], r[123]
        );
        P!(
            r[12], r[13], r[28], r[29], r[44], r[45], r[60], r[61], r[76], r[77], r[92], r[93],
            r[108], r[109], r[124], r[125]
        );
        P!(
            r[14], r[15], r[30], r[31], r[46], r[47], r[62], r[63], r[78], r[79], r[94], r[95],
            r[110], r[111], r[126], r[127]
        );

        r.iter_mut()
            .zip(x.iter().zip(y.iter()))
            .for_each(|(a, (&b, &c))| *a ^= b ^ c);

        r
    }
}

impl KDF for Argon2 {
    fn max_key_size(&self) -> usize {
        self.tag_len() as usize
    }

    /// key_size必须是self.tag_len()
    fn kdf(&mut self, key_size: usize) -> Result<Vec<u8>, CipherError> {
        if key_size != self.tag_len() as usize {
            return Err(CipherError::InvalidKeySize {
                real: self.tag_len() as usize,
                target: Some(key_size),
            });
        }

        let b = self.generate_block();
        let mut bf = b[self.q() as usize - 1];
        for l in 1..self.p() {
            let last_block_in_lane = l * self.q() + self.q() - 1;
            bf.iter_mut()
                .zip(b[last_block_in_lane as usize])
                .for_each(|(a, b)| {
                    *a ^= b;
                });
        }

        let data = bf
            .into_iter()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<_>>();

        Ok(Self::var_len_hash(
            &mut self.blake2b,
            &[data.as_slice()],
            key_size as u32,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::kdf::argon::ParamsBuilder;
    use crate::KDF;

    #[test]
    fn argon2d() {
        let mut argon2d = ParamsBuilder::argon2d()
            .mem_size(32)
            .number_of_passes(3)
            .degree_of_parallelism(4)
            .tag_len(32)
            .build_with_secret_associated(
                vec![0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03],
                vec![
                    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                ],
            )
            .unwrap()
            .argon2(
                vec![
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                ],
                vec![
                    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                    0x02, 0x02, 0x02,
                ],
            )
            .unwrap();

        let key = argon2d.kdf(32).unwrap();

        let tgt = vec![
            0x51u8, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97, 0x53, 0x71, 0xd3, 0x09, 0x19, 0x73,
            0x42, 0x94, 0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1, 0xa1, 0x3a, 0x4d, 0xb9,
            0xfa, 0xbe, 0x4a, 0xcb,
        ];

        assert_eq!(key, tgt);
    }

    #[test]
    fn argon2i() {
        let mut argon2i = ParamsBuilder::argon2i()
            .mem_size(32)
            .number_of_passes(3)
            .degree_of_parallelism(4)
            .tag_len(32)
            .build_with_secret_associated(
                vec![0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03],
                vec![
                    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                ],
            )
            .unwrap()
            .argon2(
                vec![
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                ],
                vec![
                    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                    0x02, 0x02, 0x02,
                ],
            )
            .unwrap();

        let key = argon2i.kdf(32).unwrap();

        let tgt = vec![
            0xc8u8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa, 0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94,
            0xbd, 0xa1, 0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2, 0x99, 0x52, 0xa4, 0xc4,
            0x67, 0x2b, 0x6c, 0xe8,
        ];

        assert_eq!(key, tgt);
    }

    #[test]
    fn argon2id() {
        let mut argon2id = ParamsBuilder::argon2id()
            .mem_size(32)
            .number_of_passes(3)
            .degree_of_parallelism(4)
            .tag_len(32)
            .build_with_secret_associated(
                vec![0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03],
                vec![
                    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                ],
            )
            .unwrap()
            .argon2(
                vec![
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                ],
                vec![
                    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                    0x02, 0x02, 0x02,
                ],
            )
            .unwrap();

        let key = argon2id.kdf(32).unwrap();

        let tgt = vec![
            0x0du8, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
            0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
            0x6b, 0x01, 0xe6, 0x59,
        ];

        assert_eq!(key, tgt);
    }
}
