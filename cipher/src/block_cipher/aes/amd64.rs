#[cfg(target_arch = "x86")]
use core::arch::x86::*;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use std::mem::transmute;

macro_rules! impl_aes_amd {
    ($NAME: ident, $BITS: literal, $ROUNDS: literal) => {
        #[derive(Clone)]
        pub struct $NAME {
            en_key: [__m128i; Self::NR_EXPAND],
            de_key: [__m128i; Self::NR_EXPAND],
        }

        impl $NAME {
            // 密钥位长度
            const KEY_BITS: usize = $BITS;
            pub const KEY_SIZE: usize = Self::KEY_BITS / 8;
            const NR: usize = $ROUNDS;
            const NR_EXPAND: usize = Self::NR + 1;
            const BLOCK_SIZE: usize = 16;

            pub fn new(key: [u8; Self::KEY_SIZE]) -> Self {
                let (en_key, de_key) = unsafe {
                    let k = Self::new_encrypt(key);
                    let dk = Self::new_decrypt(&k);
                    (k, dk)
                };

                Self { en_key, de_key }
            }

            #[target_feature(enable = "aes", enable = "sse2")]
            unsafe fn new_decrypt(
                en_key: &[__m128i; Self::NR_EXPAND],
            ) -> [__m128i; Self::NR_EXPAND] {
                let mut de_key = [_mm_undefined_si128(); Self::NR_EXPAND];

                de_key[0] = en_key[Self::NR_EXPAND - 1];
                de_key[Self::NR_EXPAND - 1] = en_key[0];

                for (i, ek) in en_key.iter().rev().enumerate().skip(1).take(Self::NR - 1) {
                    de_key[i] = _mm_aesimc_si128(*ek);
                }

                de_key
            }

            #[target_feature(enable = "aes", enable = "sse2")]
            unsafe fn encrypt_block_inner_(
                &self,
                data: &[u8; Self::BLOCK_SIZE],
            ) -> [u8; Self::BLOCK_SIZE] {
                let tmp = _mm_loadu_si128(transmute(data.as_ptr()));
                let mut tmp = _mm_xor_si128(tmp, self.en_key[0]);
                self.en_key
                    .iter()
                    .skip(1)
                    .take(Self::NR - 1)
                    .for_each(|&e| {
                        tmp = _mm_aesenc_si128(tmp, e);
                    });
                tmp = _mm_aesenclast_si128(tmp, self.en_key[Self::NR_EXPAND - 1]);
                let mut buf = [0u8; Self::BLOCK_SIZE];
                _mm_storeu_si128(transmute(buf.as_mut_ptr()), tmp);
                buf
            }

            pub(super) fn encrypt_block_inner(
                &self,
                data: &[u8; Self::BLOCK_SIZE],
            ) -> [u8; Self::BLOCK_SIZE] {
                unsafe { self.encrypt_block_inner_(data) }
            }

            #[target_feature(enable = "aes", enable = "sse2")]
            unsafe fn decrypt_block_inner_(
                &self,
                data: &[u8; Self::BLOCK_SIZE],
            ) -> [u8; Self::BLOCK_SIZE] {
                let tmp = _mm_loadu_si128(transmute(data.as_ptr()));
                let mut tmp = _mm_xor_si128(tmp, self.de_key[0]);
                self.de_key
                    .iter()
                    .skip(1)
                    .take(Self::NR - 1)
                    .for_each(|&e| {
                        tmp = _mm_aesdec_si128(tmp, e);
                    });
                tmp = _mm_aesdeclast_si128(tmp, self.de_key[Self::NR_EXPAND - 1]);
                let mut buf = [0u8; Self::BLOCK_SIZE];
                _mm_storeu_si128(transmute(buf.as_mut_ptr()), tmp);
                buf
            }

            pub(super) fn decrypt_block_inner(
                &self,
                data: &[u8; Self::BLOCK_SIZE],
            ) -> [u8; Self::BLOCK_SIZE] {
                unsafe { self.decrypt_block_inner_(data) }
            }
        }
    };
}

impl_aes_amd!(AES128, 128, 10);
impl_aes_amd!(AES192, 192, 12);
impl_aes_amd!(AES256, 256, 14);

impl AES128 {
    #[target_feature(enable = "sse2")]
    unsafe fn new_encrypt_assist(temp1: __m128i, temp2: __m128i) -> __m128i {
        let temp2 = _mm_shuffle_epi32(temp2, 0xff);
        let temp3 = _mm_slli_si128(temp1, 0x4);
        let temp1 = _mm_xor_si128(temp1, temp3);
        let temp3 = _mm_slli_si128(temp3, 0x4);
        let temp1 = _mm_xor_si128(temp1, temp3);
        let temp3 = _mm_slli_si128(temp3, 0x4);
        let temp1 = _mm_xor_si128(temp1, temp3);
        _mm_xor_si128(temp1, temp2)
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    unsafe fn new_encrypt(key: [u8; Self::KEY_SIZE]) -> [__m128i; Self::NR_EXPAND] {
        let mut en_key = [_mm_undefined_si128(); Self::NR_EXPAND];
        en_key[0] = _mm_loadu_si128(transmute(key.as_ptr()));
        macro_rules! key_expand {
            ($KEY: ident, [$IDX: literal, $IMM: literal]) => {
                let temp2 = _mm_aeskeygenassist_si128($KEY[$IDX - 1], $IMM);
                $KEY[$IDX] = Self::new_encrypt_assist($KEY[$IDX - 1], temp2);
            };
            ($KEY: ident, [$IDX1: literal, $IMM1: literal], $([$IDX2: literal, $IMM2: literal]),+) => {
                key_expand!($KEY, [$IDX1, $IMM1]);
                key_expand!($KEY, $([$IDX2, $IMM2]),+);
            }
        }

        key_expand!(
            en_key,
            [1, 0x1],
            [2, 0x2],
            [3, 0x4],
            [4, 0x8],
            [5, 0x10],
            [6, 0x20],
            [7, 0x40],
            [8, 0x80],
            [9, 0x1b],
            [10, 0x36]
        );

        en_key
    }
}

impl AES192 {
    #[target_feature(enable = "sse2")]
    #[inline]
    unsafe fn cvt_i2d(temp: *const __m128i) -> __m128d {
        _mm_load_pd(transmute(temp))
    }

    #[target_feature(enable = "sse2")]
    #[inline]
    unsafe fn cvt_d2i(temp: *const __m128d) -> __m128i {
        _mm_loadu_si128(transmute(temp))
    }

    #[target_feature(enable = "sse2")]
    unsafe fn new_encrypt_assist(
        temp1: __m128i,
        temp2: __m128i,
        temp3: __m128i,
    ) -> (__m128i, __m128i) {
        let temp2 = _mm_shuffle_epi32(temp2, 0x55);
        let temp4 = _mm_slli_si128(temp1, 0x4);
        let temp1 = _mm_xor_si128(temp1, temp4);
        let temp4 = _mm_slli_si128(temp4, 0x4);
        let temp1 = _mm_xor_si128(temp1, temp4);
        let temp4 = _mm_slli_si128(temp4, 0x4);
        let temp1 = _mm_xor_si128(temp1, temp4);
        let temp1 = _mm_xor_si128(temp1, temp2);
        let temp2 = _mm_shuffle_epi32(temp1, 0xff);
        let temp4 = _mm_slli_si128(temp3, 0x4);
        let temp3 = _mm_xor_si128(temp3, temp4);
        let temp3 = _mm_xor_si128(temp3, temp2);
        (temp1, temp3)
    }

    #[allow(unused_assignments)]
    #[target_feature(enable = "aes", enable = "sse2")]
    unsafe fn new_encrypt(key: [u8; Self::KEY_SIZE]) -> [__m128i; Self::NR_EXPAND] {
        let mut key1 = [0u8; 32];
        key1[0..Self::KEY_SIZE].copy_from_slice(&key);
        let key = key1;

        let mut en_key = [_mm_undefined_si128(); Self::NR_EXPAND];
        en_key[0] = _mm_loadu_si128(transmute(key.as_ptr()));
        let mut temp3 = _mm_loadu_si128(transmute(key.as_ptr().offset(16)));
        macro_rules! key_expand {
            ($KEY: ident, $TEMP3: ident, [$IDX: literal, $IMM: literal]) => {
                let temp2_ = _mm_aeskeygenassist_si128 ($TEMP3, $IMM);
                let (temp1_, temp3_) = Self::new_encrypt_assist($KEY[$IDX - 1], temp2_, $TEMP3);
                let (x, y) = (Self::cvt_i2d(&$TEMP3), Self::cvt_i2d(&temp1_));
                en_key[$IDX] = Self::cvt_d2i(&_mm_shuffle_pd(x, y, 0));
                en_key[$IDX+1] = Self::cvt_d2i(&_mm_shuffle_pd(Self::cvt_i2d(&temp1_), Self::cvt_i2d(&temp3_), 1));
                let temp2_ = _mm_aeskeygenassist_si128 (temp3_, $IMM << 1);
                let (temp1_, temp3_) = Self::new_encrypt_assist(temp1_, temp2_, temp3_);
                en_key[$IDX+2] = temp1_;
                $TEMP3 = temp3_;
            };
            ($KEY: ident, $TEMP3: ident, [$IDX1: literal, $IMM1: literal], $([$IDX2: literal, $IMM2: literal]),+) => {
                key_expand!($KEY, $TEMP3, [$IDX1, $IMM1]);
                key_expand!($KEY, $TEMP3, $([$IDX2, $IMM2]),+);
            }
        }

        key_expand!(en_key, temp3, [1, 0x1], [4, 0x4], [7, 0x10], [10, 0x40]);

        en_key
    }
}

impl AES256 {
    #[target_feature(enable = "sse2")]
    unsafe fn new_encrypt_assist1(temp1: __m128i, temp2: __m128i) -> __m128i {
        let temp2 = _mm_shuffle_epi32(temp2, 0xff);
        let temp4 = _mm_slli_si128(temp1, 0x4);
        let temp1 = _mm_xor_si128(temp1, temp4);
        let temp4 = _mm_slli_si128(temp4, 0x4);
        let temp1 = _mm_xor_si128(temp1, temp4);
        let temp4 = _mm_slli_si128(temp4, 0x4);
        let temp1 = _mm_xor_si128(temp1, temp4);
        _mm_xor_si128(temp1, temp2)
    }

    #[target_feature(enable = "sse2")]
    unsafe fn new_encrypt_assist2(temp1: __m128i, temp3: __m128i) -> __m128i {
        let temp4 = _mm_aeskeygenassist_si128(temp1, 0x0);
        let temp2 = _mm_shuffle_epi32(temp4, 0xaa);
        let temp4 = _mm_slli_si128(temp3, 0x4);
        let temp3 = _mm_xor_si128(temp3, temp4);
        let temp4 = _mm_slli_si128(temp4, 0x4);
        let temp3 = _mm_xor_si128(temp3, temp4);
        let temp4 = _mm_slli_si128(temp4, 0x4);
        let temp3 = _mm_xor_si128(temp3, temp4);
        _mm_xor_si128(temp3, temp2)
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    unsafe fn new_encrypt(key: [u8; Self::KEY_SIZE]) -> [__m128i; Self::NR_EXPAND] {
        let mut en_key = [_mm_undefined_si128(); Self::NR_EXPAND];

        en_key[0] = _mm_loadu_si128(transmute(key.as_ptr()));
        en_key[1] = _mm_loadu_si128(transmute(key.as_ptr().offset(16)));

        macro_rules! key_expand {
            ($KEY: ident, [$IDX: literal, $IMM: literal]) => {
                let temp2 = _mm_aeskeygenassist_si128 ($KEY[$IDX - 1], $IMM);
                en_key[$IDX] = Self::new_encrypt_assist1($KEY[$IDX - 2], temp2);
                en_key[$IDX+1] = Self::new_encrypt_assist2($KEY[$IDX], $KEY[$IDX - 1]);
            };
            ($KEY: ident, [$IDX1: literal, $IMM1: literal], $([$IDX2: literal, $IMM2: literal]),+) => {
                key_expand!($KEY, [$IDX1, $IMM1]);
                key_expand!($KEY, $([$IDX2, $IMM2]),+);
            }
        }

        key_expand!(
            en_key,
            [2, 0x1],
            [4, 0x2],
            [6, 0x4],
            [8, 0x8],
            [10, 0x10],
            [12, 0x20]
        );

        let temp2 = _mm_aeskeygenassist_si128(en_key[Self::NR_EXPAND - 2], 0x40);
        en_key[Self::NR_EXPAND - 1] = Self::new_encrypt_assist1(en_key[Self::NR_EXPAND - 3], temp2);

        en_key
    }
}
