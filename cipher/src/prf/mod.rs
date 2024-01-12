use crate::CipherError;

pub trait PRF {
    fn update_key(&mut self, key: Vec<u8>) -> Result<(), CipherError>;

    fn prf(&mut self, x: &[u8]) -> Vec<u8>;

    fn prf_with_key(&mut self, key: Vec<u8>, x: &[u8]) -> Result<Vec<u8>, CipherError> {
        self.update_key(key)?;
        Ok(self.prf(x))
    }
}

pub use crate::mac::HMAC;
