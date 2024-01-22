use crypto_hash::sha2::SHA256;
use rand::DefaultRand;

use crate::{Sign, Verify};

use super::{ECDSAWithP224, ECDSAWithP256, ECDSAWithP384, ECDSAWithP521};

fn cases() -> Vec<&'static str> {
    vec![
        "this is test",
        "sky",
        "algorithm",
        "nihon",
        r#"Elliptic curve cryptography (ECC) has uses in applications involving digital signatures (e.g.,
Elliptic Curve Digital Signature Algorithm [ECDSA]) and key agreement schemes (e.g., Elliptic
Curve Diffie-Hellman [ECDH]). Historically, elliptic curves have usually been expressed in
short Weierstrass format. However, curves that are expressed using a different format, such as
Montgomery curves and twisted Edwards curves, have gone from garnering academic interest to
being deployed in a number of applications. These curves can provide better performance and
increased side-channel resistance."#,
    ]
}

#[test]
fn p224_sigature() {
    let (hasher, rng) = (SHA256::default(), DefaultRand::default());
    let mut p224 = ECDSAWithP224::auto_generate_key(hasher, rng).unwrap();
    let mut sig = Vec::with_capacity(512);

    for case in cases() {
        sig.clear();
        p224.sign(case.as_bytes(), &mut sig).unwrap();
        p224.verify(case.as_bytes(), sig.as_slice()).unwrap();
    }
}

#[test]
fn p256_sigature() {
    let (hasher, rng) = (SHA256::default(), DefaultRand::default());
    let mut p256 = ECDSAWithP256::auto_generate_key(hasher, rng).unwrap();
    let mut sig = Vec::with_capacity(512);

    for case in cases() {
        sig.clear();
        p256.sign(case.as_bytes(), &mut sig).unwrap();
        p256.verify(case.as_bytes(), sig.as_slice()).unwrap();
    }
}

#[test]
fn p384_sigature() {
    let (hasher, rng) = (SHA256::default(), DefaultRand::default());
    let mut p384 = ECDSAWithP384::auto_generate_key(hasher, rng).unwrap();
    let mut sig = Vec::with_capacity(512);

    for case in cases() {
        sig.clear();
        p384.sign(case.as_bytes(), &mut sig).unwrap();
        p384.verify(case.as_bytes(), sig.as_slice()).unwrap();
    }
}

#[test]
fn p521_sigature() {
    let (hasher, rng) = (SHA256::default(), DefaultRand::default());
    let mut p521 = ECDSAWithP521::auto_generate_key(hasher, rng).unwrap();
    let mut sig = Vec::with_capacity(512);

    for case in cases() {
        sig.clear();
        p521.sign(case.as_bytes(), &mut sig).unwrap();
        p521.verify(case.as_bytes(), sig.as_slice()).unwrap();
    }
}
