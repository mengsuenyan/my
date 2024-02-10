use super::AES;
use utils::Block;
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

macro_rules! impl_aes {
    (
        $NAME: ident,
        $KEY_BITS: literal,
        $NR: literal
    ) => {
        #[derive(Clone)]
        pub struct $NAME {
            en_key: [u32; Self::NK_EXPAND],
            de_key: [u32; Self::NK_EXPAND],
        }

        impl $NAME {
            // 密钥位长度
            const KEY_BITS: usize = $KEY_BITS;
            // 字位长度
            const WORD_BITS: usize = 32;
            pub const KEY_SIZE: usize = Self::KEY_BITS / 8;
            // 密钥字长
            const NK: usize = Self::KEY_BITS / Self::WORD_BITS;
            // 加密轮数
            const NR: usize = $NR;
            // 密钥派生(KEY Schedule)后的密钥字长度
            const NK_EXPAND: usize = (Self::NR + 1) << 2;
            const BLOCK_SIZE: usize = 16;

            pub fn new(key: [u8; Self::KEY_SIZE]) -> Self {
                let en_key = Self::new_encrypt(key);
                let de_key = Self::new_decrypt(&en_key);
                Self { en_key, de_key }
            }

            // 密钥扩展
            fn new_encrypt(key: [u8; Self::KEY_SIZE]) -> [u32; Self::NK_EXPAND] {
                let mut key_expand = [0u32; Self::NK_EXPAND];

                for (k, chunk) in key_expand.iter_mut().zip(key.chunks_exact(4)) {
                    *k = u32::from_be_bytes(Block::to_arr_uncheck(chunk));
                }

                for i in Self::NK..Self::NK_EXPAND {
                    let tmp = key_expand[i - 1];
                    let t = if (i % Self::NK) == 0 {
                        AES::sub_word(tmp.rotate_left(8)) ^ AES::POWX[(i / Self::NK) - 1]
                    } else if (Self::NK > 6) && ((i % Self::NK) == 4) {
                        AES::sub_word(tmp)
                    } else {
                        tmp
                    };
                    key_expand[i] = key_expand[i - Self::NK] ^ t;
                }

                #[cfg(feature = "sec-zeroize")]
                {
                    let mut key = key;
                    key.zeroize();
                }

                key_expand
            }

            fn new_decrypt(key: &[u32; Self::NK_EXPAND]) -> [u32; Self::NK_EXPAND] {
                let mut key_expand = [0u32; Self::NK_EXPAND];

                for i in (0..key_expand.len()).step_by(4) {
                    let ei = key_expand.len() - i - 4;
                    for j in 0..4 {
                        let mut x = key[ei + j];
                        if i > 0 && (i + 4) < key_expand.len() {
                            let v = x.to_be_bytes();
                            let (v0, v1, v2, v3) =
                                (v[0] as usize, v[1] as usize, v[2] as usize, v[3] as usize);
                            x = AES::TD0[AES::SBOX0[v0] as usize]
                                ^ AES::TD1[AES::SBOX0[v1] as usize]
                                ^ AES::TD2[AES::SBOX0[v2] as usize]
                                ^ AES::TD3[AES::SBOX0[v3] as usize];
                        }

                        key_expand[i + j] = x;
                    }
                }

                key_expand
            }

            pub(super) fn decrypt_block_inner(
                &self,
                data: &[u8; Self::BLOCK_SIZE],
            ) -> [u8; Self::BLOCK_SIZE] {
                let mut block = [0u32; Self::BLOCK_SIZE / 4];
                for (b, chunk) in block.iter_mut().zip(data.chunks_exact(4)) {
                    *b = u32::from_be_bytes(Block::to_arr_uncheck(chunk));
                }

                let key = &self.de_key;
                // AddRoundKey
                let (mut s0, mut s1, mut s2, mut s3) = (
                    block[0] ^ key[0],
                    block[1] ^ key[1],
                    block[2] ^ key[2],
                    block[3] ^ key[3],
                );

                // SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
                let mut k = 4;
                for _ in 0..(Self::NR - 1) {
                    let (v0, v1, v2, v3) = (
                        s0.to_be_bytes(),
                        s1.to_be_bytes(),
                        s2.to_be_bytes(),
                        s3.to_be_bytes(),
                    );
                    let t0 = key[k]
                        ^ AES::TD0[v0[0] as usize]
                        ^ AES::TD1[v3[1] as usize]
                        ^ AES::TD2[v2[2] as usize]
                        ^ AES::TD3[v1[3] as usize];
                    let t1 = key[k + 1]
                        ^ AES::TD0[v1[0] as usize]
                        ^ AES::TD1[v0[1] as usize]
                        ^ AES::TD2[v3[2] as usize]
                        ^ AES::TD3[v2[3] as usize];
                    let t2 = key[k + 2]
                        ^ AES::TD0[v2[0] as usize]
                        ^ AES::TD1[v1[1] as usize]
                        ^ AES::TD2[v0[2] as usize]
                        ^ AES::TD3[v3[3] as usize];
                    let t3 = key[k + 3]
                        ^ AES::TD0[v3[0] as usize]
                        ^ AES::TD1[v2[1] as usize]
                        ^ AES::TD2[v1[2] as usize]
                        ^ AES::TD3[v0[3] as usize];
                    s0 = t0;
                    s1 = t1;
                    s2 = t2;
                    s3 = t3;
                    k += 4;
                }

                // SubBytes -> ShiftRows -> AddRoundKey
                let (v0, v1, v2, v3) = (
                    s0.to_be_bytes(),
                    s1.to_be_bytes(),
                    s2.to_be_bytes(),
                    s3.to_be_bytes(),
                );
                let tmp0 = [
                    AES::SBOX1[v0[0] as usize],
                    AES::SBOX1[v3[1] as usize],
                    AES::SBOX1[v2[2] as usize],
                    AES::SBOX1[v1[3] as usize],
                ];
                let tmp1 = [
                    AES::SBOX1[v1[0] as usize],
                    AES::SBOX1[v0[1] as usize],
                    AES::SBOX1[v3[2] as usize],
                    AES::SBOX1[v2[3] as usize],
                ];
                let tmp2 = [
                    AES::SBOX1[v2[0] as usize],
                    AES::SBOX1[v1[1] as usize],
                    AES::SBOX1[v0[2] as usize],
                    AES::SBOX1[v3[3] as usize],
                ];
                let tmp3 = [
                    AES::SBOX1[v3[0] as usize],
                    AES::SBOX1[v2[1] as usize],
                    AES::SBOX1[v1[2] as usize],
                    AES::SBOX1[v0[3] as usize],
                ];
                s0 = u32::from_be_bytes(tmp0);
                s1 = u32::from_be_bytes(tmp1);
                s2 = u32::from_be_bytes(tmp2);
                s3 = u32::from_be_bytes(tmp3);
                s0 ^= key[k];
                s1 ^= key[k + 1];
                s2 ^= key[k + 2];
                s3 ^= key[k + 3];

                let mut plaintext = [0u8; Self::BLOCK_SIZE];
                let (s0, s1, s2, s3) = (
                    s0.to_be_bytes(),
                    s1.to_be_bytes(),
                    s2.to_be_bytes(),
                    s3.to_be_bytes(),
                );
                plaintext[0] = s0[0];
                plaintext[1] = s0[1];
                plaintext[2] = s0[2];
                plaintext[3] = s0[3];
                plaintext[4] = s1[0];
                plaintext[5] = s1[1];
                plaintext[6] = s1[2];
                plaintext[7] = s1[3];
                plaintext[8] = s2[0];
                plaintext[9] = s2[1];
                plaintext[10] = s2[2];
                plaintext[11] = s2[3];
                plaintext[12] = s3[0];
                plaintext[13] = s3[1];
                plaintext[14] = s3[2];
                plaintext[15] = s3[3];
                plaintext
            }

            pub(super) fn encrypt_block_inner(
                &self,
                data: &[u8; Self::BLOCK_SIZE],
            ) -> [u8; Self::BLOCK_SIZE] {
                let mut block = [0u32; Self::BLOCK_SIZE / 4];
                for (b, chunk) in block.iter_mut().zip(data.chunks_exact(4)) {
                    *b = u32::from_be_bytes(Block::to_arr_uncheck(chunk));
                }

                let key = &self.en_key;
                // AddRoundKey
                let (mut s0, mut s1, mut s2, mut s3) = (
                    block[0] ^ key[0],
                    block[1] ^ key[1],
                    block[2] ^ key[2],
                    block[3] ^ key[3],
                );

                // SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
                let mut k = 4;
                for _ in 0..(Self::NR - 1) {
                    let (v0, v1, v2, v3) = (
                        s0.to_be_bytes(),
                        s1.to_be_bytes(),
                        s2.to_be_bytes(),
                        s3.to_be_bytes(),
                    );
                    let t0 = key[k]
                        ^ AES::TE0[v0[0] as usize]
                        ^ AES::TE1[v1[1] as usize]
                        ^ AES::TE2[v2[2] as usize]
                        ^ AES::TE3[v3[3] as usize];
                    let t1 = key[k + 1]
                        ^ AES::TE0[v1[0] as usize]
                        ^ AES::TE1[v2[1] as usize]
                        ^ AES::TE2[v3[2] as usize]
                        ^ AES::TE3[v0[3] as usize];
                    let t2 = key[k + 2]
                        ^ AES::TE0[v2[0] as usize]
                        ^ AES::TE1[v3[1] as usize]
                        ^ AES::TE2[v0[2] as usize]
                        ^ AES::TE3[v1[3] as usize];
                    let t3 = key[k + 3]
                        ^ AES::TE0[v3[0] as usize]
                        ^ AES::TE1[v0[1] as usize]
                        ^ AES::TE2[v1[2] as usize]
                        ^ AES::TE3[v2[3] as usize];
                    s0 = t0;
                    s1 = t1;
                    s2 = t2;
                    s3 = t3;
                    k += 4;
                }

                // SubBytes -> ShiftRows -> AddRoundKey
                let (v0, v1, v2, v3) = (
                    s0.to_be_bytes(),
                    s1.to_be_bytes(),
                    s2.to_be_bytes(),
                    s3.to_be_bytes(),
                );
                let tmp0 = [
                    AES::SBOX0[v0[0] as usize],
                    AES::SBOX0[v1[1] as usize],
                    AES::SBOX0[v2[2] as usize],
                    AES::SBOX0[v3[3] as usize],
                ];
                let tmp1 = [
                    AES::SBOX0[v1[0] as usize],
                    AES::SBOX0[v2[1] as usize],
                    AES::SBOX0[v3[2] as usize],
                    AES::SBOX0[v0[3] as usize],
                ];
                let tmp2 = [
                    AES::SBOX0[v2[0] as usize],
                    AES::SBOX0[v3[1] as usize],
                    AES::SBOX0[v0[2] as usize],
                    AES::SBOX0[v1[3] as usize],
                ];
                let tmp3 = [
                    AES::SBOX0[v3[0] as usize],
                    AES::SBOX0[v0[1] as usize],
                    AES::SBOX0[v1[2] as usize],
                    AES::SBOX0[v2[3] as usize],
                ];
                s0 = u32::from_be_bytes(tmp0);
                s1 = u32::from_be_bytes(tmp1);
                s2 = u32::from_be_bytes(tmp2);
                s3 = u32::from_be_bytes(tmp3);
                s0 ^= key[k];
                s1 ^= key[k + 1];
                s2 ^= key[k + 2];
                s3 ^= key[k + 3];

                let mut ciphertext = [0u8; Self::BLOCK_SIZE];
                let (s0, s1, s2, s3) = (
                    s0.to_be_bytes(),
                    s1.to_be_bytes(),
                    s2.to_be_bytes(),
                    s3.to_be_bytes(),
                );
                ciphertext[0] = s0[0];
                ciphertext[1] = s0[1];
                ciphertext[2] = s0[2];
                ciphertext[3] = s0[3];
                ciphertext[4] = s1[0];
                ciphertext[5] = s1[1];
                ciphertext[6] = s1[2];
                ciphertext[7] = s1[3];
                ciphertext[8] = s2[0];
                ciphertext[9] = s2[1];
                ciphertext[10] = s2[2];
                ciphertext[11] = s2[3];
                ciphertext[12] = s3[0];
                ciphertext[13] = s3[1];
                ciphertext[14] = s3[2];
                ciphertext[15] = s3[3];
                ciphertext
            }
        }

        #[cfg(feature = "sec-zeroize")]
        impl Zeroize for $NAME {
            fn zeroize(&mut self) {
                self.en_key.zeroize();
                self.de_key.zeroize();
            }
        }
    };
}

impl AES {
    #[inline]
    pub(super) const fn sub_word(w: u32) -> u32 {
        let i = w.to_be_bytes();
        u32::from_be_bytes([
            AES::SBOX0[i[0] as usize],
            AES::SBOX0[i[1] as usize],
            AES::SBOX0[i[2] as usize],
            AES::SBOX0[i[3] as usize],
        ])
    }
}

impl_aes!(AES128, 128, 10);
impl_aes!(AES192, 192, 12);
impl_aes!(AES256, 256, 14);
