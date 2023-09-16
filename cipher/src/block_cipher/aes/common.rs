use crate::CipherError;

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

    pub fn aes128(key: &[u8]) -> Result<AES128, CipherError> {
        if key.len() == AES128::KEY_BYTES {
            let key = unsafe {
                let ptr = key.as_ptr() as *const [u8; AES128::KEY_BYTES];
                ptr.read()
            };

            Ok(AES128::new(key))
        } else {
            Err(CipherError::InvalidKeySize {
                target: AES128::KEY_BYTES,
                real: key.len(),
            })
        }
    }

    pub fn aes192(key: &[u8]) -> Result<AES192, CipherError> {
        if key.len() == AES192::KEY_BYTES {
            let key = unsafe {
                let ptr = key.as_ptr() as *const [u8; AES192::KEY_BYTES];
                ptr.read()
            };

            Ok(AES192::new(key))
        } else {
            Err(CipherError::InvalidKeySize {
                target: AES128::KEY_BYTES,
                real: key.len(),
            })
        }
    }

    pub fn aes256(key: &[u8]) -> Result<AES256, CipherError> {
        if key.len() == AES256::KEY_BYTES {
            let key = unsafe {
                let ptr = key.as_ptr() as *const [u8; AES256::KEY_BYTES];
                ptr.read()
            };

            Ok(AES256::new(key))
        } else {
            Err(CipherError::InvalidKeySize {
                target: AES128::KEY_BYTES,
                real: key.len(),
            })
        }
    }
}
