//! SP 800-186: Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters
//!
//! W_(a,b) short weierstrass curve : y² = x³ + a * x + b
//!
//! M_(A, B) montgomery curve: B * v² = u³ + A * u² + u
//!
//! E_(a,d) twisted edwards curve:  a * x² + y² = 1 + d * x² * y²
//!
//!
//! M_(A, B)和E_(a,d)之间是双映射关系, 参数有如下关系(SP 800-186):
//! a = (A + 2) / B; d = (A - 2) / B;
//! A = 2(a + d) / (a - d); B = 4 / (a - d);
//! (x, y) = (u / v, (u - 1) / (u + 1));
//! (u, v) = ((1 + y) / (1 - y), (1+y) / ((1-y) * x))
//!

pub mod curve25519;
pub mod curve448;
pub mod p224;
pub mod p256;
pub mod p384;
pub mod p521;
pub mod w25519;
pub mod w448;
