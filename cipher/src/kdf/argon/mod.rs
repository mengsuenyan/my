//! RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
//!

mod params;

pub use params::{Params, ParamsBuilder};

mod argon2;
pub use argon2::Argon2;
