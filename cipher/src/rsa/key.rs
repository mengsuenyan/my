//! 参考notebook 'RSA密码学规范PKCS1_v_2_2.md'
use crate::{CipherError, Rand};
use num_bigint::{BigInt, BigUint};
use num_traits::{Euclid, One, Zero};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::iter::{Chain, Once};
use utils::{BigIntExt, BigUintExt};

#[derive(Clone, Debug, PartialOrd, PartialEq, Ord, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    // n = p * q
    n: BigUint,
    // public exponent, gcd(e, (p-1)(q-1)) = 1
    e: BigUint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKey {
    pk: PublicKey,
    // d * e = 1 % lambda(n)
    // lambda(n) = (p-1)(q-1)*r1*...*ri*...
    d: BigUint,
    // p'=pi
    // n = p1 * p2 * pi..., i>=2
    // p1 = p
    // p2 = q
    factor: Option<PrimeFactor>,
}

// n = p * q * r1 * ... * ri * ...
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PrimeFactor {
    p: BigInt,
    q: BigInt,
    r: Vec<BigInt>,
    // 预计算值, 加速私钥的计算
    pre: PrecomputedValues,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CRTValue {
    // d % (ri-1)
    di: BigInt,
    //Ri: rm = r1 * r2 * ... r_(i-1), r0 = p * q
    rm: BigInt,
    // CRT coefficients: $r \cdot coeff \equiv 1 \mod prime$
    // rm^{-1} % ri
    ti: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PrecomputedValues {
    // $e \cdot d_p \equiv 1 \mod (p-1)$
    // d % (p - 1)
    d_p: BigInt,
    // $e \cdot d_q \equiv 1 \mod (q-1)$
    // d % (q - 1)
    d_q: BigInt,
    // $q \cdot q_inv \equiv 1 \mod p$
    // q^{-1} % p
    q_inv: BigInt,

    // CRTValues is used for the 3rd and subsequent primes. Due to a
    // historical accident, the CRT for the first two primes is handled
    // differently in PKCS#1 and interoperability is sufficiently
    // important that we mirror this.
    crt_val: Vec<CRTValue>,
}

impl PublicKey {
    /// n: RSA modules
    /// e: public key exponent
    /// note: not to check the `n` and `exp` are right RSA parameters
    pub fn new_uncheck(n: BigUint, exp: BigUint) -> Self {
        Self { e: exp, n }
    }

    /// note: not to check the `n` and `exp` are right RSA parameters
    pub fn from_be_bytes(n: &[u8], exp: &[u8]) -> Self {
        Self {
            e: BigUint::from_bytes_be(exp),
            n: BigUint::from_bytes_be(n),
        }
    }

    /// note: not to check the `n` and `exp` are right RSA parameters
    pub fn from_le_bytes(n: &[u8], exp: &[u8]) -> Self {
        Self {
            e: BigUint::from_bytes_le(exp),
            n: BigUint::from_bytes_le(n),
        }
    }

    /// n
    pub fn modules(&self) -> &BigUint {
        &self.n
    }

    /// e
    pub fn exponent(&self) -> &BigUint {
        &self.e
    }

    /// $m^e \mod n, m \lt n$
    fn rsaep_uncheck(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }

    /// RSAEP: RSA Encrypt primitive
    pub fn rsaep(&self, m: &BigUint) -> Result<BigUint, CipherError> {
        if m < &self.n {
            Ok(self.rsaep_uncheck(m))
        } else {
            Err(CipherError::Other(format!(
                "rsaep: invalid message that need less than {:#x}",
                self.n
            )))
        }
    }

    pub fn is_valid(&self) -> Result<(), CipherError> {
        if self.e < BigUint::from(2u8) {
            Err(CipherError::InvalidPublicKey(format!(
                "rsa: public key {:#x} is too small",
                self.e
            )))
        } else if self.e > BigUint::from(u32::MAX - 1) {
            Err(CipherError::InvalidPublicKey(format!(
                "rsa: public key {:#x} is too large",
                self.e
            )))
        } else {
            Ok(())
        }
    }
}

impl PrivateKey {
    pub fn new_uncheck(modulus: BigUint, public_exp: BigUint, private_exp: BigUint) -> Self {
        Self {
            pk: PublicKey::new_uncheck(modulus, public_exp),
            d: private_exp,
            factor: None,
        }
    }

    pub fn new_uncheck_with_factor(d: BigUint, p: BigUint, q: BigUint, r: Vec<BigUint>) -> Self {
        let (mut n, mut totient) = (&p * &q, (&p - 1u32) * (&q - 1u32));
        for ri in r.iter() {
            n *= ri;
            totient *= ri - 1u32;
        }
        let d = BigInt::from(d);
        let e = BigIntExt(&d)
            .modinv(&BigInt::from(totient))
            .unwrap()
            .to_biguint()
            .unwrap();
        let d = d.to_biguint().unwrap();
        let pk = PublicKey::new_uncheck(n, e);

        let precomputed = PrecomputedValues::new(&p, &q, &d, r.as_slice());
        let r = r.into_iter().map(BigInt::from).collect();
        let factor = PrimeFactor {
            p: BigInt::from(p),
            q: BigInt::from(q),
            r,
            pre: precomputed,
        };

        Self {
            pk,
            d,
            factor: Some(factor),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }

    /// RSADP: RSA Decrypt primitive
    pub fn rsadp(&self, c: &BigUint) -> Result<BigUint, CipherError> {
        if c < &self.pk.n {
            Ok(self.rsadp_uncheck(c))
        } else {
            Err(CipherError::Other(format!(
                "rsadp: invalid cipher message {:#x} that need less than {:#x}",
                c, self.pk.n
            )))
        }
    }

    // m1 = c^{dp}, m2 = c^{dq}
    // mi = c^{di}, i >= 3...
    // h = (m1 - m2) * qinv % p
    // m = m2 + q * h
    // mi = c^{di} % ri
    // m = m + Ri * ((mi - m) * ti % ri)
    fn rsadp_uncheck(&self, c: &BigUint) -> BigUint {
        match self.factor.as_ref() {
            Some(factor) => {
                let c = BigInt::from(c.clone());
                let (mut m1, m2) = (
                    c.modpow(&factor.pre.d_p, &factor.p),
                    c.modpow(&factor.pre.d_q, &factor.q),
                );
                // h * q
                m1 -= &m2;
                m1 *= &factor.pre.q_inv;
                let (mut h, mut m) = (m1.rem_euclid(&factor.p), m2);
                h *= &factor.q;
                m += h;

                // mi = c^{di} % ri
                // m = m + Ri * ((mi - m) * ti % ri)
                for (crt, ri) in factor.pre.crt_val.iter().zip(factor.r.iter()) {
                    let mut mi = c.modpow(&crt.di, ri);
                    mi -= &m;
                    mi *= &crt.ti;
                    let mut tmp = mi.rem_euclid(ri);
                    tmp *= &crt.rm;
                    m += tmp;
                }

                m.to_biguint()
                    .expect("this always can be converted to biguint")
            }
            None => c.modpow(&self.d, &self.pk.n),
        }
    }

    pub fn is_valid(&self) -> Result<(), CipherError> {
        let mut n = BigInt::one();
        let factor = self
            .factor
            .as_ref()
            .ok_or(CipherError::Other("rsa: factor doesn't exist".to_string()))?;
        for prime in factor.iter() {
            if prime.is_zero() || prime.is_one() {
                return Err(CipherError::InvalidPrivateKey(
                    "rsa: invalid prime value".to_string(),
                ));
            }

            n *= prime;
        }

        if n != self.pk.n.clone().into() {
            return Err(CipherError::InvalidPrivateKey(
                "rsa: invalid modulus".to_string(),
            ));
        }

        // d*e
        let de: BigInt = (&self.d * &self.pk.e).into();
        for prime in factor.iter() {
            let pm1 = prime - 1u8;
            let m = &de % pm1;
            if !m.is_one() {
                return Err(CipherError::InvalidPrivateKey(
                    "rsa: invalid exponent".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// This method convert from golang source code.
    /// GenerateMultiPrimeKey generates a multi-prime RSA keypair of the given bit
    /// size and the given random source, as suggested in [1]. Although the public
    /// keys are compatible (actually, indistinguishable) from the 2-prime case,
    /// the private keys are not. Thus it may not be possible to export multi-prime
    /// private keys in certain formats or to subsequently import them into other
    /// code.
    ///
    /// Table 1 in [2] suggests maximum numbers of primes for a given size.
    ///
    /// [1] US patent 4405829 (1972, expired)
    /// [2] http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
    ///
    /// `prime_test_rounds`(n) means the number of test rounds, for any odd number that great than 2 and positive integer n, the probability of error
    /// in MillerRabinPrimeTest is at most $2^{-n}$.
    ///
    /// 生成`n_primes`素数的私钥, `n = p * q * r1 * ... * ri * ...r_{n-2}`
    pub fn generate_multi_prime_key<Rng: Rand>(
        n_primes: usize,
        bits_len: usize,
        prime_test_rounds: usize,
        rd: &mut Rng,
    ) -> Result<PrivateKey, CipherError> {
        if n_primes < 2 {
            return Err(CipherError::Other(format!(
                "rsa: invalid n_primes `{}`",
                n_primes
            )));
        }

        if bits_len < 64 {
            let prime_limit = (1u64 << (bits_len / n_primes)) as f64;
            // pi approximates the number of primes less than primeLimit
            let mut pi = prime_limit / (prime_limit.ln() - 1f64);

            // Generated primes start with 11 (in binary) so we can only
            // use a quarter of them.
            pi /= 4f64;
            // Use a factor of two to ensure that key generation terminates
            // in a reasonable amount of time.
            pi /= 2f64;
            if pi <= (n_primes as f64) {
                return Err(CipherError::Other(
                    "rsa: too few primes of given length to generatge an rsa key".to_string(),
                ));
            }
        }

        let (pub_exp, mut primes) = (
            BigUintExt(BigUint::from(65537u32)),
            Vec::with_capacity(n_primes),
        );
        let (pri_exp, modulus) = 'next_set_of_primes: loop {
            primes.clear();
            let mut cbits = bits_len;
            // crypto/rand should set the top two bits in each prime.
            // Thus each prime has the form
            //   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
            // And the product is:
            //   P = 2^cbits × α
            // where α is the product of nprimes numbers of the form 0.11...
            //
            // If α < 1/2 (which can happen for nprimes > 2), we need to
            // shift cbits to compensate for lost bits: the mean value of 0.11...
            // is 7/8, so cbits + shift - nprimes * log2(7/8) ~= bits - 1/2
            // will give good results.
            if n_primes >= 7 {
                cbits += (n_primes - 2) / 5
            }

            for i in 0..n_primes {
                let prime = BigUintExt::<BigUint>::generate_prime(
                    cbits / (n_primes - i),
                    prime_test_rounds,
                    rd,
                )?;

                cbits -= prime.bits() as usize;
                primes.push(prime);
            }

            // Make sure that primes is pairwise unequal.
            primes.dedup();
            if primes.len() != n_primes {
                continue 'next_set_of_primes;
            }

            let (mut n, mut totient) = (BigUint::from(1u32), BigUint::from(1u32));
            for prime in primes.iter() {
                n *= prime;
                let pm1 = prime - 1u32;
                totient *= pm1;
            }

            if n.bits() as usize != bits_len {
                // This should never happen for n_primes == 2 because
                // crypto/rand should set the top two bits in each prime.
                // For n_primes > 2 we hope it does not happen often.
                continue 'next_set_of_primes;
            }

            if let Some(inv) = pub_exp.modinv(&totient) {
                break (inv, n);
            }
        };

        let precomputed = PrecomputedValues::new(&primes[0], &primes[1], &pri_exp, &primes[2..]);

        let factor = PrimeFactor {
            p: BigInt::from(primes[0].clone()),
            q: BigInt::from(primes[1].clone()),
            r: primes.into_iter().skip(2).map(|x| x.into()).collect(),
            pre: precomputed,
        };

        Ok(Self {
            pk: PublicKey::new_uncheck(modulus, pub_exp.0),
            d: pri_exp,
            factor: Some(factor),
        })
    }

    /// `generate_key` generates an RSA keypair of the given bit size using the
    /// random source random (for example, crypto/rand.Reader).
    ///
    /// `prime_test_rounds`(n) means the number of test rounds, for any odd number that great than 2 and positive integer n, the probability of error
    /// in MillerRabinPrimeTest is at most $2^{-n}$.
    pub fn generate_key<R: Rand>(
        bits_len: usize,
        prime_test_rounds: usize,
        rd: &mut R,
    ) -> Result<PrivateKey, CipherError> {
        Self::generate_multi_prime_key(2, bits_len, prime_test_rounds, rd)
    }
}

type PrimeFactorIter<'a> =
    Chain<Chain<Once<&'a BigInt>, Once<&'a BigInt>>, std::slice::Iter<'a, BigInt>>;
impl PrimeFactor {
    fn iter(&self) -> PrimeFactorIter {
        use std::iter::once;
        once(&self.p).chain(once(&self.q)).chain(self.r.iter())
    }
}

impl PrecomputedValues {
    // r: r2 ... , 不包括r0(p), r1(q)
    fn new(p: &BigUint, q: &BigUint, d: &BigUint, r: &[BigUint]) -> Self {
        let one = BigUint::one();
        let (d_p, d_q, q_inv) = (
            d % (p - &one),
            d % (q - &one),
            BigUintExt(q)
                .modinv(p)
                .expect("this will never happened due to q and q is coprime"),
        );

        // R
        let (mut rm, mut crt) = (p * q, Vec::with_capacity(r.len()));

        for r in r.iter() {
            // d * di = 1 % (ri - 1)
            let di = d % (r - &one);
            // R * ti = 1 % ri
            let ti = BigUintExt(&rm)
                .modinv(r)
                .expect("this will never happened due to R and r is coprime");

            crt.push(CRTValue {
                di: BigInt::from(di),
                rm: BigInt::from(rm.clone()),
                ti: BigInt::from(ti),
            });

            rm *= r;
        }

        Self {
            d_p: BigInt::from(d_p),
            d_q: BigInt::from(d_q),
            q_inv: BigInt::from(q_inv),
            crt_val: crt,
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{n={:#x}, e={:#x}}}", self.n, self.e)
    }
}

impl Display for PrimeFactor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        s.push('[');
        for (i, r) in self.r.iter().enumerate() {
            if i != 0 {
                s.push(',');
            }
            s.push_str(format!("{:#x}", r).as_str());
        }
        s.push(']');
        write!(f, "{{p:{:#x}, q:{:#x}, r: {}}}", self.p, self.q, s)
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.factor.as_ref() {
            Some(factor) => {
                write!(
                    f,
                    "{{pk: {}, d: {:#x}, factor: {}}}",
                    self.pk, self.d, factor
                )
            }
            None => {
                write!(f, "{{pk: {}, d: {:#x}, factor: []}}", self.pk, self.d)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rsa::key::PrivateKey;
    use crate::DefaultRand;
    use num_bigint::BigUint;
    use num_traits::Num;

    fn keygen(bits_len: usize, n_primes: usize) {
        let mut rng = DefaultRand::default();
        let key = PrivateKey::generate_multi_prime_key(n_primes, bits_len, 19, &mut rng).unwrap();
        assert_eq!(
            key.public_key().modules().bits() as usize,
            bits_len,
            "the modulus bits len is wrong"
        );
    }

    fn key_basics(key: &PrivateKey) {
        key.is_valid().unwrap();
        assert!(
            key.public_key().exponent() <= key.public_key().modules(),
            "private exponent too large"
        );
        let m = BigUint::from(42u32);
        let c = key.public_key().rsaep_uncheck(&m);
        let m2 = key.rsadp_uncheck(&c);
        assert_eq!(m, m2, "encrypt message != decrypt message");
    }

    #[test]
    fn rsa_keygen_1024() {
        keygen(1024, 2);
    }

    #[test]
    fn rsa_multi3_prime_keygen() {
        keygen(768, 3);
    }

    #[test]
    fn rsa_multi4_prime_keygen() {
        keygen(768, 4);
    }

    #[test]
    fn rsa_multin_prime_keygen() {
        let (bits_len, max_n_primes) = (64, 24);

        for n in 5..max_n_primes {
            keygen(64 + bits_len * n, n);
        }
    }

    #[test]
    fn gnu_tls_key() {
        let n = BigUint::from_str_radix("290684273230919398108010081414538931343", 10).unwrap();
        let e = BigUint::from(65537u32);
        let d = BigUint::from_str_radix("31877380284581499213530787347443987241", 10).unwrap();
        let (p, q) = (
            BigUint::from_str_radix("16775196964030542637", 10).unwrap(),
            BigUint::from_str_radix("17328218193455850539", 10).unwrap(),
        );

        let pk = PrivateKey::new_uncheck_with_factor(d, p, q, vec![]);
        assert_eq!(&e, pk.public_key().exponent());
        assert_eq!(&n, pk.public_key().modules());

        key_basics(&pk);
    }

    #[test]
    fn rsa_keygen_2048() {
        keygen(2048, 2);

        let n = BigUint::from_str_radix("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557", 10).unwrap();
        let e = BigUint::from(3u32);
        let d = BigUint::from_str_radix("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731", 10).unwrap();
        let (p, q) = (
           BigUint::from_str_radix("130903255182996722426771613606077755295583329135067340152947172868415809027537376306193179624298874215608270802054347609836776473930072411958753044562214537013874103802006369634761074377213995983876788718033850153719421695468704276694983032644416930879093914927146648402139231293035971427838068945045019075433",10).unwrap(),
           BigUint::from_str_radix("109348945610485453577574767652527472924289229538286649661240938988020367005475727988253438647560958573506159449538793540472829815903949343191091817779240101054552748665267574271163617694640513549693841337820602726596756351006149518830932261246698766355347898158548465400674856021497190430791824869615170301029",10).unwrap(),
            );

        let pk = PrivateKey::new_uncheck_with_factor(d, p, q, vec![]);

        assert_eq!(&e, pk.public_key().exponent());
        assert_eq!(&n, pk.public_key().modules());

        key_basics(&pk);
    }
}
