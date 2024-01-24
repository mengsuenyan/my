use std::io::Write;

use crypto_hash::{sha2, DigestX};
use group::curve::edwards25519::{Affine, Fq, Fr, Projective};
use group::ec::{AffineRepr, CurveGroup, Group};
use group::ff::{BigInteger, MontFp, PrimeField};

use crate::{CipherError, Sign, Verify};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ed25519PublicKey {
    // RFC8032 编码后的公钥
    pk: [u8; 32],
    point_q: Affine,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Ed25519PrivateKey {
    prefix: [u8; 32],
    // 私钥d: Clamping(SHA2-512(seed)[0..32])
    d: Fr,
    pk: Ed25519PublicKey,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Ed25519Key {
    PublicKey(Ed25519PublicKey),
    PrivateKey(Ed25519PrivateKey),
}

#[derive(Clone, PartialEq, Hash, Debug)]
pub struct Ed25519 {
    key: Ed25519Key,
    dom_prefix: Vec<u8>,
    // Ed25519需是空的
    // Ed25519ctx, Ed25519ph应该指定context
    ctx: Vec<u8>,
    // Ed25519ph, 会对消息SHA2-512哈希后再签名
    pre_hash: bool,
}

impl Ed25519PublicKey {
    /// RFC 8032 chapter 5.1.4规范生成的公私钥;
    /// 小端序;
    /// 公钥: y || (x % 2), y是255位, 再加上x标志位
    pub fn new(public_key: &[u8]) -> Result<Self, CipherError> {
        let pk: [u8; 32] = public_key.try_into().map_err(|_e| {
            CipherError::Other("eddsa: invalid encode public key byte length".to_string())
        })?;
        let point_q = Self::compute_public_key(pk.as_slice())?;

        Ok(Self { pk, point_q })
    }

    fn compute_public_key(pk: &[u8]) -> Result<Affine, CipherError> {
        let mut b = pk.to_vec();
        let y_last = b.last_mut().unwrap();

        let is_odd_x = (*y_last >> 7) == 1;
        *y_last &= 0x7f;
        let y = <Fq as PrimeField>::from_le_bytes_mod_order(b.as_slice());
        let Some((x1, x2)) = Affine::get_xs_from_y_unchecked(y) else {
            return Err(CipherError::Other(
                "eddsa: cannot recover x from point y".to_string(),
            ));
        };

        let (b1, b2) = (x1.into_bigint(), x2.into_bigint());

        if !(b1.is_odd() ^ b2.is_odd()) {
            return Err(CipherError::Other("eddsa: recover x failed".to_string()));
        }

        let x = if b1.is_odd() == is_odd_x { x1 } else { x2 };
        let point_q = Affine::new_unchecked(x, y);
        if !point_q.is_on_curve() {
            Err(CipherError::Other(
                "eddsa: public key not no the curve".to_string(),
            ))
        } else if !point_q.is_in_correct_subgroup_assuming_on_curve() {
            Err(CipherError::Other(
                "eddsa: public key order not in the subgroup".to_string(),
            ))
        } else {
            Ok(point_q)
        }
    }

    /// RFC8032 经过编码的公钥
    pub fn rfc8032_public_key(&self) -> [u8; 32] {
        self.pk
    }

    pub fn public_key(&self) -> Affine {
        self.point_q
    }
}

impl Ed25519PrivateKey {
    /// RFC 8032 chapter 5.1.4规范生成的公私钥;
    /// seed: RFC 8032长度seed长度要求32, 本实现不对此做限制, 结果不影响;
    /// 私钥: d = SHA2-512(seed)[..32];
    /// 公钥: d * G;
    ///
    pub fn new(seed: &[u8]) -> Result<Self, CipherError> {
        let (d, prefix) = Self::derive_private_key(seed);
        let point_q = Ed25519::scalar_base_point(d).into_affine();
        let pk = Ed25519::convert_to_bytes(point_q);
        if pk.len() != 32 {
            return Err(CipherError::Other(
                "eddsa: public key encoding byte length must equal to 32".to_string(),
            ));
        }

        let pk: [u8; 32] = pk.try_into().unwrap();
        Ok(Self {
            prefix,
            d,
            pk: Ed25519PublicKey { pk, point_q },
        })
    }

    pub fn private_key(&self) -> &Fr {
        &self.d
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.pk
    }

    fn derive_private_key(seed: &[u8]) -> (Fr, [u8; 32]) {
        let mut sha512 = sha2::SHA512::new();
        let h = sha512.digest(seed);
        let d = Ed25519::clamping(&h[..32]);
        (d, h[32..].try_into().unwrap())
    }
}

impl Ed25519Key {
    pub fn public_key(&self) -> &Ed25519PublicKey {
        match self {
            Self::PublicKey(pk) => pk,
            Self::PrivateKey(key) => key.public_key(),
        }
    }

    pub fn private_key(&self) -> Option<&Ed25519PrivateKey> {
        if let Self::PrivateKey(key) = &self {
            Some(key)
        } else {
            None
        }
    }
}

impl From<Ed25519PrivateKey> for Ed25519Key {
    fn from(value: Ed25519PrivateKey) -> Self {
        Self::PrivateKey(value)
    }
}

impl From<Ed25519PublicKey> for Ed25519Key {
    fn from(value: Ed25519PublicKey) -> Self {
        Self::PublicKey(value)
    }
}

impl Ed25519 {
    /// `context`: 当指定该参数时, 使用的Ed25519ph, Ed25519ctx算法. `context`的字节长度需要小于`256`;
    /// `is_pre_hash`: 指定为`true`时使用的Ed25519ph算法, 会将消息SHA2-512哈希之后签名/验证. 否则, Ed25519ctx;
    pub fn new(
        key: Ed25519Key,
        context: Option<&[u8]>,
        is_pre_hash: bool,
    ) -> Result<Self, CipherError> {
        let (ctx, dom_prefix) = if let Some(ctx) = context {
            if ctx.len() > 255 {
                return Err(CipherError::ValidateFailed(
                    "eddsa: context byte length need less than 256".to_string(),
                ));
            }

            if is_pre_hash {
                (
                    ctx.to_vec(),
                    b"SigEd25519 no Ed25519 collisions\x01".to_vec(),
                )
            } else {
                (
                    ctx.to_vec(),
                    b"SigEd25519 no Ed25519 collisions\x00".to_vec(),
                )
            }
        } else {
            (Vec::with_capacity(0), Vec::with_capacity(0))
        };

        Ok(Self {
            key,
            dom_prefix,
            ctx,
            pre_hash: is_pre_hash,
        })
    }

    fn scalar_base_point(r: Fr) -> Projective {
        let g = Projective::generator();
        g * r
    }

    fn convert_to_bytes(p: Affine) -> Vec<u8> {
        let x = (p.x().unwrap().into_bigint().is_odd() as u8) << 7;
        let mut y = p.y().unwrap().into_bigint().to_bytes_le();
        y.resize(32, 0);
        if let Some(last) = y.last_mut() {
            *last |= x;
        }
        y
    }

    // ensure `x.len() == 64`
    fn convert_to_scalar_in_uniform(x: &[u8]) -> Fr {
        // 2^(168) % n
        const R168: Fr = MontFp!("374144419156711147060143317175368453031918731001856");
        // 2^(336) % n
        const R336: Fr =
            MontFp!("7237005577331725599505074253122254557748324176651437972075682554507211166701");
        let s = <Fr as PrimeField>::from_le_bytes_mod_order(&x[..21]);
        let t = <Fr as PrimeField>::from_le_bytes_mod_order(&x[21..42]);
        let s = s + (t * R168);
        let t = <Fr as PrimeField>::from_le_bytes_mod_order(&x[42..64]);
        s + (t * R336)
    }

    fn clamping(x: &[u8]) -> Fr {
        let mut w = x.to_vec();
        w.resize(64, 0);
        w[0] &= 248;
        w[31] &= 63;
        w[31] |= 64;
        Self::convert_to_scalar_in_uniform(&w)
    }

    fn sign_inner(&mut self, msg: &[u8], sig: &mut Vec<u8>) -> Result<(), CipherError> {
        let mut sha512 = sha2::SHA512::new();
        let (prefix, d) = (
            self.key.private_key().unwrap().prefix,
            self.key.private_key().unwrap().d,
        );

        sha512.reset_x();
        if !self.dom_prefix.is_empty() {
            sha512.write_all(&self.dom_prefix).unwrap();
            sha512
                .write_all(&(self.ctx.len() as u8).to_le_bytes())
                .unwrap();
            sha512.write_all(&self.ctx).unwrap();
        }
        sha512.write_all(&prefix).unwrap();
        sha512.write_all(msg).unwrap();
        let r = sha512.finish_x();
        let r = Self::convert_to_scalar_in_uniform(&r);
        let point_r = Self::scalar_base_point(r).into_affine();
        let mut point_r = Self::convert_to_bytes(point_r);

        sha512.reset_x();
        if !self.dom_prefix.is_empty() {
            sha512.write_all(&self.dom_prefix).unwrap();
            sha512
                .write_all(&(self.ctx.len() as u8).to_le_bytes())
                .unwrap();
            sha512.write_all(&self.ctx).unwrap();
        }
        sha512.write_all(&point_r).unwrap();
        sha512
            .write_all(&self.key.public_key().rfc8032_public_key())
            .unwrap();
        sha512.write_all(msg).unwrap();
        let u = sha512.finish_x();
        let u = Self::convert_to_scalar_in_uniform(&u);
        let s = r + (u * d);
        let mut s = s.into_bigint().to_bytes_le();
        s.resize(32, 0);

        sig.append(&mut point_r);
        sig.append(&mut s);

        Ok(())
    }

    pub fn verify_inner(&mut self, msg: &[u8], sig: &[u8]) -> Result<(), CipherError> {
        if sig.len() != 64 {
            return Err(CipherError::ValidateFailed(
                "eddsa: invalid signature length".to_string(),
            ));
        } else if sig[63] & 224 != 0 {
            return Err(CipherError::ValidateFailed(
                "eddsa: invalid signature s".to_string(),
            ));
        }

        let (pk, point_q) = (self.key.public_key().pk, self.key.public_key().point_q);

        let mut sha512 = sha2::SHA512::new();
        if !self.dom_prefix.is_empty() {
            sha512.write_all(&self.dom_prefix).unwrap();
            sha512
                .write_all(&(self.ctx.len() as u8).to_le_bytes())
                .unwrap();
            sha512.write_all(&self.ctx).unwrap();
        }
        sha512.write_all(&sig[..32]).unwrap();
        sha512.write_all(&pk).unwrap();
        sha512.write_all(msg).unwrap();
        let u = sha512.finish_x();
        let u = Self::convert_to_scalar_in_uniform(&u);

        let s = <Fr as PrimeField>::from_le_bytes_mod_order(&sig[32..]);
        let s = Self::scalar_base_point(s);
        let point_q = -point_q;
        let u = point_q * u;

        let point_r = (s + u).into_affine();
        let r = Self::convert_to_bytes(point_r);

        if r != sig[..32] {
            Err(CipherError::ValidateFailed(
                "eddsa: invalid signature".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn set_ed25519ph(&mut self, ctx: &[u8]) -> Result<(), CipherError> {
        if ctx.len() > 255 {
            Err(CipherError::ValidateFailed(
                "eddsa: context byte length need less than 256".to_string(),
            ))
        } else {
            self.ctx.clear();
            self.ctx.extend_from_slice(ctx);
            self.dom_prefix.clear();
            self.dom_prefix
                .extend(b"SigEd25519 no Ed25519 collisions\x01");
            Ok(())
        }
    }

    pub fn set_ed25519ctx(&mut self, ctx: &[u8]) -> Result<(), CipherError> {
        if ctx.len() > 255 {
            Err(CipherError::ValidateFailed(
                "eddsa: context byte length need less than 256".to_string(),
            ))
        } else {
            self.ctx.clear();
            self.ctx.extend_from_slice(ctx);
            self.dom_prefix.clear();
            self.dom_prefix
                .extend(b"SigEd25519 no Ed25519 collisions\x00");
            Ok(())
        }
    }

    pub fn set_ed25519(&mut self) -> Result<(), CipherError> {
        self.dom_prefix.clear();
        self.ctx.clear();
        Ok(())
    }
}

impl Sign for Ed25519 {
    fn sign(&mut self, msg: &[u8], sign: &mut Vec<u8>) -> Result<(), CipherError> {
        if self.key.private_key().is_none() {
            return Err(CipherError::Other("eddsa: no private key".to_string()));
        }

        if self.pre_hash {
            let mut sha512 = sha2::SHA512::default();
            let msg = sha512.digest(msg);
            self.sign_inner(&msg, sign)
        } else {
            self.sign_inner(msg, sign)
        }
    }
}

impl Verify for Ed25519 {
    fn verify(&mut self, msg: &[u8], sig: &[u8]) -> Result<(), CipherError> {
        if self.pre_hash {
            let mut sha512 = sha2::SHA512::default();
            let msg = sha512.digest(msg);
            self.verify_inner(&msg, sig)
        } else {
            self.verify_inner(msg, sig)
        }
    }
}

#[cfg(test)]
mod tests {
    use group::ec::CurveGroup;
    use num_bigint::BigUint;
    use num_traits::{Num, ToBytes};

    use crate::{
        dss::eddsa::{Ed25519, Ed25519PrivateKey},
        Sign, Verify,
    };

    use super::Ed25519PublicKey;

    #[test]
    fn clamping() {
        // (case, tgt)
        let cases = [
            (
                "633d368491364dc9cd4c1bf891b1d59460face1644813240a313e61f2c88216e",
                "1d87a9026fd0126a5736fe1628c95dd419172b5b618457e041c9c861b2494a94",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "693e47972caf527c7883ad1b39822f026f47db2ab0e1919955b8993aa04411d1",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "12e9a68b73fd5aacdbcaf3e88c46fea6ebedb1aa84eed1842f07f8edab65e3a7",
            ),
        ];

        for (case_s, tgt_s) in cases {
            let (case, tgt) = (
                BigUint::from_str_radix(case_s, 16).unwrap().to_be_bytes(),
                BigUint::from_str_radix(tgt_s, 16).unwrap().to_be_bytes(),
            );
            let r = Ed25519::clamping(&case);
            let p = Ed25519::scalar_base_point(r).into_affine();
            let p = Ed25519::convert_to_bytes(p);
            assert_eq!(tgt, p, "case {} failed", case_s);
        }
    }

    #[test]
    fn sign() {
        // (msg, key, sig, dom, txt)
        let cases = [
            ("616263", "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf", "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406", true, ""),
            ("f726936d19c800494e3fdaff20b276a8", "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292", "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d", false, "foo"),
        ];

        for (msg_s, key_s, sig_s, dom_s, ctx_s) in cases {
            let (msg_data, key, mut sig, pre_hash, ctx) = (
                BigUint::from_str_radix(msg_s, 16).unwrap().to_be_bytes(),
                BigUint::from_str_radix(key_s, 16).unwrap().to_be_bytes(),
                BigUint::from_str_radix(sig_s, 16).unwrap().to_be_bytes(),
                dom_s,
                ctx_s.as_bytes(),
            );

            let seed = &key[..32];
            let key = Ed25519PrivateKey::new(seed).unwrap();
            let mut ed25519 = Ed25519::new(key.into(), Some(ctx), pre_hash).unwrap();
            let mut r_s = Vec::with_capacity(64);
            ed25519.sign(&msg_data, &mut r_s).unwrap();
            let r_s = format!("{:x}", BigUint::from_bytes_be(&r_s));
            assert_eq!(sig_s, r_s, "case {} failed", msg_s);
            ed25519.verify(&msg_data, &sig).unwrap();

            sig[0] ^= 0xff;
            assert!(
                ed25519.verify(&msg_data, &sig).is_err(),
                "invalid signature accept"
            );
            sig[0] ^= 0xff;
            *sig.last_mut().unwrap() ^= 0xff;
            assert!(
                ed25519.verify(&msg_data, &sig).is_err(),
                "invalid signature accept"
            );
        }
    }

    #[test]
    fn malleability() {
        // https://tools.ietf.org/html/rfc8032#section-5.1.7 adds an additional test
        // that s be in [0, order). This prevents someone from adding a multiple of
        // order to s and obtaining a second valid signature for the same message.
        let msg = [0x54u8, 0x65, 0x73, 0x74];
        let sig = [
            0x7cu8, 0x38, 0xe0, 0x26, 0xf2, 0x9e, 0x14, 0xaa, 0xbd, 0x05, 0x9a, 0x0f, 0x2d, 0xb8,
            0xb0, 0xcd, 0x78, 0x30, 0x40, 0x60, 0x9a, 0x8b, 0xe6, 0x84, 0xdb, 0x12, 0xf8, 0x2a,
            0x27, 0x77, 0x4a, 0xb0, 0x67, 0x65, 0x4b, 0xce, 0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f,
            0x6f, 0x5d, 0xaf, 0xc0, 0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57, 0x33, 0x36,
            0xa5, 0xc5, 0x1e, 0xb6, 0xf9, 0x46, 0xb3, 0x1d,
        ];
        let public_key = [
            0x7du8, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5, 0x22, 0xab, 0xbe,
            0xe6, 0x85, 0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34, 0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36,
            0x9e, 0xf5, 0x49, 0xfa,
        ];

        let pk = Ed25519PublicKey::new(&public_key).unwrap();

        let mut ed25519 = Ed25519::new(pk.into(), None, false).unwrap();
        ed25519.verify(&msg, &sig).unwrap();
    }
}
