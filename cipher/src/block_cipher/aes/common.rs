use crate::CipherError;
use utils::Block;

use super::{AES, AES128, AES192, AES256};

impl AES {
    pub fn new(key: &[u8]) -> Result<AES, CipherError> {
        match key.len() {
            AES128::KEY_SIZE => AES::aes128(key).map(AES::AES128),
            AES192::KEY_SIZE => AES::aes192(key).map(AES::AES192),
            AES256::KEY_SIZE => AES::aes256(key).map(AES::AES256),
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
                target: Some(AES128::KEY_SIZE),
                real: key.len(),
            }),
            Some(key) => Ok(AES128::new(key)),
        }
    }

    pub fn aes192(key: &[u8]) -> Result<AES192, CipherError> {
        match Block::to_arr(key) {
            None => Err(CipherError::InvalidKeySize {
                target: Some(AES192::KEY_SIZE),
                real: key.len(),
            }),
            Some(key) => Ok(AES192::new(key)),
        }
    }

    pub fn aes256(key: &[u8]) -> Result<AES256, CipherError> {
        match Block::to_arr(key) {
            None => Err(CipherError::InvalidKeySize {
                target: Some(AES256::KEY_SIZE),
                real: key.len(),
            }),
            Some(key) => Ok(AES256::new(key)),
        }
    }
}
