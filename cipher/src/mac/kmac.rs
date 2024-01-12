pub use crypto_hash::cshake::{KMACXof, KMAC};
use crypto_hash::XOF;

use crate::MAC;

impl<const R: usize> MAC for KMAC<R> {
    fn block_size_x(&self) -> usize {
        (Self::BLOCK_BITS + 7) >> 3
    }
    fn digest_size_x(&self) -> usize {
        self.desired_len()
    }

    fn reset(&mut self) {
        XOF::reset(self)
    }

    fn mac(&mut self) -> Vec<u8> {
        self.finalize()
    }
}

impl<const R: usize> MAC for KMACXof<R> {
    fn block_size_x(&self) -> usize {
        (Self::BLOCK_BITS + 7) >> 3
    }

    fn digest_size_x(&self) -> usize {
        self.desired_len()
    }

    fn reset(&mut self) {
        XOF::reset(self)
    }

    fn mac(&mut self) -> Vec<u8> {
        self.finalize()
    }
}
