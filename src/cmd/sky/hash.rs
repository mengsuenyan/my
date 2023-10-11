use crypto_hash::sha3;
use crypto_hash::DigestX;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SkyHash {
    SHA3_256,
}

impl SkyHash {
    pub fn hash_fn(self) -> Box<dyn DigestX> {
        match self {
            Self::SHA3_256 => Box::new(sha3::SHA256::new()),
        }
    }
}
