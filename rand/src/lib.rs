pub trait Rand: Default {
    fn rand(&mut self, random: &mut [u8]);
}

mod default_rand;
pub use default_rand::DefaultRand;

impl<T: xrand::RngCore + Default> Rand for T {
    fn rand(&mut self, random: &mut [u8]) {
        let mut r = Self::default();
        r.fill_bytes(random);
    }
}
