use crypto_hash::DigestX;
use group::{
    ec::{AffineRepr, CurveGroup, Group},
    ff::{BigInteger, Field, PrimeField},
};
use num_traits::Zero;
use rand::Rand;

use crate::{CipherError, Sign, Verify};

use super::{Key, PrivateKey, PublicKey, Signature};

pub struct ECDSA<Curve: CurveGroup, Hasher: DigestX, Rng: Rand> {
    key: Key<Curve>,
    hasher: Hasher,
    rng: Rng,
}

impl<C: CurveGroup, H: DigestX, R: Rand> ECDSA<C, H, R> {
    pub fn new_uncheck(key: Key<C>, hasher: H, rng: R) -> Result<Self, CipherError> {
        Ok(Self { key, hasher, rng })
    }

    pub fn auto_generate_key(hasher: H, mut rng: R) -> Result<Self, CipherError> {
        let g = C::generator();
        let d = Self::nonce(&mut rng);
        let q = (g * d).into_affine();

        let key = Key::from(PrivateKey::new_uncheck(PublicKey::new_uncheck(q), d));

        Ok(Self { key, hasher, rng })
    }

    fn nonce(rng: &mut R) -> <C as Group>::ScalarField {
        let p = <<C as Group>::ScalarField as PrimeField>::MODULUS;
        let mut b = vec![0u8; (p.num_bits() as usize + 7) >> 3];

        loop {
            rng.rand(b.as_mut());
            let nonce = <C as Group>::ScalarField::from_le_bytes_mod_order(b.as_slice());
            if !nonce.is_zero() {
                break <C as Group>::ScalarField::from(nonce);
            }
        }
    }

    pub const fn curve_order_byte_size() -> usize {
        (<<C as Group>::ScalarField as PrimeField>::MODULUS_BIT_SIZE as usize + 7) >> 3
    }

    fn hash_msg_to_scalar(&mut self, msg: &[u8]) -> <C as Group>::ScalarField {
        let l_n = Self::curve_order_byte_size();
        self.hasher.reset_x();
        self.hasher.write_all(msg).unwrap();
        let mut h = self.hasher.finish_x();
        h.truncate(l_n);
        <C as Group>::ScalarField::from_be_bytes_mod_order(h.as_slice())
    }

    fn sign_inner(&mut self, msg: &[u8]) -> Result<Signature, CipherError> {
        let e = self.hash_msg_to_scalar(msg);
        let key = self
            .key
            .private_key()
            .ok_or(CipherError::InvalidPrivateKey(
                "ecdsa: no private key".to_string(),
            ))?;

        let g = C::generator();
        let (r, s) = loop {
            let (r, k_inv) = loop {
                let k = Self::nonce(&mut self.rng);
                let k_inv = k.inverse().ok_or(CipherError::Other(
                    "ecdsa: scalar element inverse doesn't exist".to_string(),
                ))?;
                let point = (g * k).into_affine();
                let x_r = *point.x().ok_or(CipherError::InvalidPublicKey(
                    "ecdsa: x_R doesn't exist".to_string(),
                ))?;

                let xr = x_r
                    .to_base_prime_field_elements()
                    .next()
                    .ok_or(CipherError::Other("ecdsa: no base prime field".to_string()))?;
                let xr = xr.into_bigint().to_bytes_be();

                let r = <C as Group>::ScalarField::from_le_bytes_mod_order(xr.as_slice());

                if !r.is_zero() {
                    break (r, k_inv);
                }
            };

            // k^(-1) * (e + r * s) mod n
            let s = r * key.private_key();
            let s = s + e;
            let s = k_inv * s;

            if !s.is_zero() {
                break (r, s);
            }
        };

        Ok(Signature::new(
            r.into_bigint().to_bytes_le(),
            s.into_bigint().to_bytes_le(),
        ))
    }

    fn verify_inner(&mut self, msg: &[u8], sig: &Signature) -> Result<(), CipherError> {
        let (r, s) = sig.to_scalar_rs::<C>()?;
        let e = self.hash_msg_to_scalar(msg);

        let s_inv = s.inverse().ok_or(CipherError::ValidateFailed(
            "ecdsa: signature s cannot inverse".to_string(),
        ))?;
        let (u, v) = (e * s_inv, r * s_inv);

        let g = C::generator();
        let pk = *self.key.public_key().as_affine();
        let point_r = ((pk * v) + (g * u)).into_affine();
        let x_r = *point_r.x().ok_or(CipherError::ValidateFailed(
            "ecdsa: cannot compute x_R".to_string(),
        ))?;

        let xr = x_r
            .to_base_prime_field_elements()
            .next()
            .ok_or(CipherError::Other("ecdsa: no base prime field".to_string()))?;
        let xr = xr.into_bigint().to_bytes_be();
        let new_r = <C as Group>::ScalarField::from_le_bytes_mod_order(xr.as_slice());

        if new_r != r {
            Err(CipherError::ValidateFailed(
                "ecdsa: invalid signature".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

impl<C: CurveGroup, H: DigestX, R: Rand> Sign for ECDSA<C, H, R> {
    /// `sign`: r || s, $n = |Curve|, len(r) = len(n), len(s) = len(n)$, r小端序, s小端序
    fn sign(&mut self, msg: &[u8], sign: &mut Vec<u8>) -> Result<(), CipherError> {
        let sig = self.sign_inner(msg)?;
        let (mut r, mut s) = (sig.r().to_vec(), sig.s().to_vec());
        let n = Self::curve_order_byte_size();
        r.resize(n, 0);
        s.resize(n, 0);
        sign.append(&mut r);
        sign.append(&mut s);

        Ok(())
    }
}

impl<C: CurveGroup, H: DigestX, R: Rand> Verify for ECDSA<C, H, R> {
    fn verify(&mut self, msg: &[u8], sign: &[u8]) -> Result<(), CipherError> {
        let n = Self::curve_order_byte_size();
        if sign.len() != (n << 1) {
            return Err(CipherError::ValidateFailed(format!(
                "invalid signature byte length `{}` that should be euqal to `{}`",
                sign.len(),
                n << 1
            )));
        }

        let (r, s) = (sign[0..n].to_vec(), sign[n..].to_vec());
        let sig = Signature::new(r, s);

        self.verify_inner(msg, &sig)?;

        Ok(())
    }
}
