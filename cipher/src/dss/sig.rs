use std::fmt::Display;

use group::{
    ec::{CurveGroup, Group},
    ff::PrimeField,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::CipherError;

/// 小端序
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Signature {
    r: Vec<u8>,
    s: Vec<u8>,
}

impl Signature {
    pub fn r(&self) -> &[u8] {
        &self.r
    }

    pub fn s(&self) -> &[u8] {
        &self.s
    }

    pub fn new(r: Vec<u8>, s: Vec<u8>) -> Self {
        Self { r, s }
    }

    pub(super) fn to_scalar_rs<C: CurveGroup>(
        &self,
    ) -> Result<(<C as Group>::ScalarField, <C as Group>::ScalarField), CipherError> {
        let (r, s) = (
            BigUint::from_bytes_le(self.r.as_slice()),
            BigUint::from_bytes_le(self.s.as_slice()),
        );

        let Ok(r) = <<C as Group>::ScalarField as PrimeField>::BigInt::try_from(r) else {
            return Err(CipherError::ValidateFailed(
                "ecdsa: invalid signature r".to_string(),
            ));
        };

        let Ok(s) = <<C as Group>::ScalarField as PrimeField>::BigInt::try_from(s) else {
            return Err(CipherError::ValidateFailed(
                "ecdsa: invalid signature s".to_string(),
            ));
        };

        <C as Group>::ScalarField::from_bigint(r)
            .zip(<C as Group>::ScalarField::from_bigint(s))
            .ok_or(CipherError::ValidateFailed(
                "ecdsa: invalid signature that must be less than curve group order".to_string(),
            ))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{r: {:x}, s: {:x}}}",
            BigUint::from_bytes_le(&self.r),
            BigUint::from_bytes_le(&self.s)
        )
    }
}
