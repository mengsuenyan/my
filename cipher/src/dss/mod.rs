//! FIPS 186-4
//! FIPS 186-5: Digital Signature Standard(DSS)
//!
//!

pub mod ecdsa;
pub use ecdsa::ECDSA;
pub mod key;
pub use key::{Key, PrivateKey, PublicKey};
pub mod sig;
pub use sig::Signature;

use group::curve::{p224, p256, p384, p521};
// p224
pub type P224Affine = p224::Affine;
pub type P224Projective = p224::Projective;
pub type P224Curve = p224::Projective;
pub type P224Key = Key<P224Curve>;
pub type ECDSAWithP224<Hasher, Rng> = ECDSA<P224Curve, Hasher, Rng>;
// p256
pub type P256Affine = p256::Affine;
pub type P256Projective = p256::Projective;
pub type P256Curve = p256::Projective;
pub type P256Key = Key<P256Curve>;
pub type ECDSAWithP256<Hasher, Rng> = ECDSA<P256Curve, Hasher, Rng>;
// p384
pub type P384Affine = p384::Affine;
pub type P384Projective = p384::Projective;
pub type P384Curve = p384::Projective;
pub type P384Key = Key<P384Curve>;
pub type ECDSAWithP384<Hasher, Rng> = ECDSA<P384Curve, Hasher, Rng>;
// p521
pub type P521Affine = p521::Affine;
pub type P521Projective = p521::Projective;
pub type P521Curve = p521::Projective;
pub type P521Key = Key<P521Curve>;
pub type ECDSAWithP521<Hasher, Rng> = ECDSA<P521Curve, Hasher, Rng>;

#[cfg(test)]
mod tests;
