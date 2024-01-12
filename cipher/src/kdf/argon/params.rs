use crate::CipherError;

use super::Argon2;

/// RFC 9106: Chapter 3.1
#[derive(Clone)]
pub struct Params {
    // p
    degree_of_paral: u32,
    // T, output length
    tag_len: u32,
    // m, 单位kb
    mem_size: u32,
    // t
    itr_num: u32,
    // K
    secret: Vec<u8>,
    // X
    associated_data: Vec<u8>,
    // y
    argon2_type: u32,
    // version number,
    ver: u32,
}

/// RFC 9106: Chapter 3.1, Chapter 4
pub struct ParamsBuilder {
    degree_of_paral: u32,
    tag_len: u32,
    mem_size: u32,
    itr_num: u32,
    argon2_type: u32,
}

impl Params {
    pub fn argon2(self, password: Vec<u8>, salt: Vec<u8>) -> Result<Argon2, CipherError> {
        Argon2::new(password, salt, self)
    }

    /// p
    pub fn degree_of_parallelism(&self) -> u32 {
        self.degree_of_paral
    }

    /// T
    pub fn tag_len(&self) -> u32 {
        self.tag_len
    }

    /// m
    pub fn mem_size(&self) -> u32 {
        self.mem_size
    }

    /// t
    pub fn num_of_passes(&self) -> u32 {
        self.itr_num
    }

    /// v
    pub fn version(&self) -> u32 {
        self.ver
    }

    /// y
    pub fn argon2_type(&self) -> u32 {
        self.argon2_type
    }

    /// K
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// X
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }

    pub fn is_argon2id(&self) -> bool {
        self.argon2_type == 0x2
    }

    pub fn is_argon2i(&self) -> bool {
        self.argon2_type == 0x1
    }

    pub fn is_argond(&self) -> bool {
        self.argon2_type == 0x00
    }
}

impl ParamsBuilder {
    /// 默认值:
    /// p: 并行个数4;
    /// T: 输出长度32字节;
    /// m: 内存大小2^21 KB;
    /// t: 迭代次数1;
    pub fn argon2id() -> Self {
        Self {
            degree_of_paral: 4,
            tag_len: 32,
            mem_size: 1 << 21,
            itr_num: 1,
            argon2_type: 2,
        }
    }

    /// 默认值:
    /// p: 并行个数4;
    /// T: 输出长度32字节;
    /// m: 内存大小2^16 KB;
    /// t: 迭代次数3;
    pub fn argon2id_with_small_mem() -> Self {
        Self {
            degree_of_paral: 4,
            tag_len: 32,
            mem_size: 1 << 16,
            itr_num: 3,
            argon2_type: 2,
        }
    }

    /// 默认值:
    /// p: 并行个数4;
    /// T: 输出长度32字节;
    /// m: 内存大小2^16 KB;
    /// t: 迭代次数1;
    pub fn argon2d() -> Self {
        Self {
            degree_of_paral: 4,
            tag_len: 32,
            mem_size: 1 << 16,
            itr_num: 1,
            argon2_type: 0,
        }
    }

    /// 默认值:
    /// p: 并行个数4;
    /// T: 输出长度32字节;
    /// m: 内存大小2^16 KB;
    /// t: 迭代次数1;
    pub fn argon2i() -> Self {
        Self {
            degree_of_paral: 4,
            tag_len: 32,
            mem_size: 1 << 16,
            itr_num: 1,
            argon2_type: 1,
        }
    }

    /// p:  并行个数, $p in [1, 1<<24)$
    pub fn degree_of_parallelism(mut self, p: u32) -> Self {
        self.degree_of_paral = p;
        self
    }

    /// tag字节长度, $T in [4, 1<<32)$
    pub fn tag_len(mut self, tag_len: u32) -> Self {
        self.tag_len = tag_len;
        self
    }

    /// m内存大小, $m in [8*p,1<<32)$
    pub fn mem_size(mut self, mem_size: u32) -> Self {
        self.mem_size = mem_size;
        self
    }

    /// t迭代次数, $t in [1, 1<<32)$
    pub fn number_of_passes(mut self, itr_numbers: u32) -> Self {
        self.itr_num = itr_numbers;
        self
    }

    fn check_params(&self) -> Result<(), CipherError> {
        if self.degree_of_paral == 0 || self.degree_of_paral >= (1u32 << 24) {
            Err(CipherError::Other(
                "argon2: p need to in the [1, 1<<24)".to_string(),
            ))
        } else if self.tag_len < 4 {
            Err(CipherError::Other(
                "argon2: T need to great than or equal to 4".to_string(),
            ))
        } else if self.mem_size < (8 * self.degree_of_paral) {
            Err(CipherError::Other(
                "argon2: m need to great than or equal to 8 * p".to_string(),
            ))
        } else if self.itr_num == 0 {
            Err(CipherError::Other(
                "argon2: t need to great than 0".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn build_with_secret_associated(
        self,
        secret: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Params, CipherError> {
        self.check_params()?;
        if associated_data.len() > (u32::MAX as usize) {
            Err(CipherError::Other(
                "argon2: associated data length need to less than 1<<32".to_string(),
            ))
        } else if secret.len() > (u32::MAX as usize) {
            Err(CipherError::Other(
                "argon2: secret length need to less than 1<<32".to_string(),
            ))
        } else {
            Ok(Params {
                degree_of_paral: self.degree_of_paral,
                tag_len: self.tag_len,
                mem_size: self.mem_size,
                itr_num: self.itr_num,
                secret,
                associated_data,
                argon2_type: self.argon2_type,
                ver: 0x13,
            })
        }
    }

    pub fn build_with_secret(self, secret: Vec<u8>) -> Result<Params, CipherError> {
        self.build_with_secret_associated(secret, Vec::with_capacity(0))
    }

    pub fn build_with_associated(self, associated_data: Vec<u8>) -> Result<Params, CipherError> {
        self.build_with_secret_associated(Vec::with_capacity(0), associated_data)
    }
}
