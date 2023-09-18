use crate::CipherError;
use utils::Block;

use super::{AES, AES128, AES192, AES256};

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

    pub fn new(key: &[u8]) -> Result<AES, CipherError> {
        match key.len() {
            AES128::KEY_BYTES => AES::aes128(key).map(AES::AES128),
            AES192::KEY_BYTES => AES::aes192(key).map(AES::AES192),
            AES256::KEY_BYTES => AES::aes256(key).map(AES::AES256),
            _ => Err(CipherError::InvalidKeySize {
                target: None,
                real: key.len(),
            }),
        }
    }

    pub(super) fn encrypt_block_inner(&self, data: &[u8; 16]) -> [u8; 16] {
        match self {
            AES::AES128(aes) => aes.encrypt_block_inner(data),
            AES::AES192(aes) => aes.encrypt_block_inner(data),
            AES::AES256(aes) => aes.encrypt_block_inner(data),
        }
    }

    pub(super) fn decrypt_block_inner(&self, data: &[u8; 16]) -> [u8; 16] {
        match self {
            AES::AES128(aes) => aes.decrypt_block_inner(data),
            AES::AES192(aes) => aes.decrypt_block_inner(data),
            AES::AES256(aes) => aes.decrypt_block_inner(data),
        }
    }

    pub fn aes128(key: &[u8]) -> Result<AES128, CipherError> {
        match Block::to_arr(key) {
            None => Err(CipherError::InvalidKeySize {
                target: Some(AES128::KEY_BYTES),
                real: key.len(),
            }),
            Some(key) => Ok(AES128::new(key)),
        }
    }

    pub fn aes192(key: &[u8]) -> Result<AES192, CipherError> {
        match Block::to_arr(key) {
            None => Err(CipherError::InvalidKeySize {
                target: Some(AES128::KEY_BYTES),
                real: key.len(),
            }),
            Some(key) => Ok(AES192::new(key)),
        }
    }

    pub fn aes256(key: &[u8]) -> Result<AES256, CipherError> {
        match Block::to_arr(key) {
            None => Err(CipherError::InvalidKeySize {
                target: Some(AES128::KEY_BYTES),
                real: key.len(),
            }),
            Some(key) => Ok(AES256::new(key)),
        }
    }
}
