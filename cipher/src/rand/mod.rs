pub trait Rand: Default {
    fn rand(&mut self, random: &mut [u8]);
}

mod default_rand;
