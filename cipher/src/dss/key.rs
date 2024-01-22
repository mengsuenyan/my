use group::ark_serialize;
use group::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use group::ec::{AffineRepr, CurveGroup, Group};
use serde::{de::Error as DeErr, ser::Error as SerdeErr, Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<T: CurveGroup> {
    point: T::Affine,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrivateKey<T: CurveGroup> {
    pk: PublicKey<T>,
    d: <T as Group>::ScalarField,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Key<T: CurveGroup> {
    PublicKey(PublicKey<T>),
    PrivateKey(PrivateKey<T>),
}

impl<T: CurveGroup> From<PublicKey<T>> for Key<T> {
    fn from(value: PublicKey<T>) -> Self {
        Self::PublicKey(value)
    }
}

impl<T: CurveGroup> From<PrivateKey<T>> for Key<T> {
    fn from(value: PrivateKey<T>) -> Self {
        Self::PrivateKey(value)
    }
}

impl<T: CurveGroup> Display for PublicKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{x: {}, y: {}}}", self.x(), self.y())
    }
}

impl<T: CurveGroup> Display for PrivateKey<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{pk: {}, d: {}}}", self.public_key(), self.d)
    }
}

impl<T: CurveGroup> Display for Key<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivateKey(k) => write!(f, "{}", k),
            Self::PublicKey(pk) => write!(f, "{}", pk),
        }
    }
}

impl<T: CurveGroup> Serialize for PublicKey<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut pk = Vec::with_capacity(1024);
        self.serialize_uncompressed(&mut pk)
            .map_err(S::Error::custom)?;
        pk.serialize(serializer)
    }
}

impl<'de, T: CurveGroup> Deserialize<'de> for PublicKey<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let pk = Vec::<u8>::deserialize(deserializer)?;
        let pk = Self::deserialize_uncompressed(pk.as_slice()).map_err(D::Error::custom)?;

        Ok(pk)
    }
}

impl<T: CurveGroup> Serialize for PrivateKey<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut key = Vec::with_capacity(1024);
        self.serialize_uncompressed(&mut key)
            .map_err(S::Error::custom)?;

        key.serialize(serializer)
    }
}

impl<'de, T: CurveGroup> Deserialize<'de> for PrivateKey<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let key = Vec::<u8>::deserialize(deserializer)?;
        let key = Self::deserialize_uncompressed(key.as_slice()).map_err(D::Error::custom)?;

        Ok(key)
    }
}

impl<T: CurveGroup> Key<T> {
    pub fn public_key(&self) -> &PublicKey<T> {
        match self {
            Self::PrivateKey(k) => k.public_key(),
            Self::PublicKey(pk) => pk,
        }
    }

    pub fn private_key(&self) -> Option<&PrivateKey<T>> {
        if let Self::PrivateKey(k) = self {
            Some(k)
        } else {
            None
        }
    }
}

impl<T: CurveGroup> PrivateKey<T> {
    pub fn public_key(&self) -> &PublicKey<T> {
        &self.pk
    }

    pub fn private_key(&self) -> &<T as Group>::ScalarField {
        &self.d
    }

    pub const fn new_uncheck(pk: PublicKey<T>, d: <T as Group>::ScalarField) -> Self {
        Self { pk, d }
    }
}

impl<T: CurveGroup> PublicKey<T> {
    pub fn x(&self) -> &T::BaseField {
        self.point.x().as_ref().unwrap()
    }

    pub fn y(&self) -> &T::BaseField {
        self.point.y().as_ref().unwrap()
    }

    pub const fn new_uncheck(point: T::Affine) -> Self {
        Self { point }
    }

    pub fn as_affine(&self) -> &T::Affine {
        &self.point
    }
}
