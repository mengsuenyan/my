use crate::Rand;
use xrand::rngs::OsRng;
use xrand::RngCore;

/// 默认使用OsRng <br>
#[derive(Copy, Clone, Default)]
pub struct DefaultRand {
    rng: OsRng,
}

impl Rand for DefaultRand {
    fn rand(&mut self, random: &mut [u8]) {
        self.rng.fill_bytes(random);
    }
}
