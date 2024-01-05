use crate::BigIntExt;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{Euclid, One, ToPrimitive, Zero};
use rand::Rand;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::ops::{Add, AddAssign, Deref, Rem, RemAssign, Sub};

pub struct BigUintExt<T: Borrow<BigUint>>(pub T);

impl<T: Borrow<BigUint>> Deref for BigUintExt<T> {
    type Target = BigUint;
    fn deref(&self) -> &Self::Target {
        self.0.borrow()
    }
}

impl<T: Borrow<BigUint>> PartialEq<Self> for BigUintExt<T> {
    fn eq(&self, other: &Self) -> bool {
        self.deref().eq(other.deref())
    }
}

impl<T: Borrow<BigUint>> Eq for BigUintExt<T> {}

impl<T: Borrow<BigUint>> PartialOrd<Self> for BigUintExt<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Borrow<BigUint>> Ord for BigUintExt<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deref().cmp(other.deref())
    }
}

impl<T: Borrow<BigUint>> PartialEq<BigUint> for BigUintExt<T> {
    fn eq(&self, other: &BigUint) -> bool {
        self.deref().eq(other)
    }
}

impl<T: Borrow<BigUint>> PartialEq<BigUint> for &BigUintExt<T> {
    fn eq(&self, other: &BigUint) -> bool {
        (*self).deref().eq(other)
    }
}

impl<T: Borrow<BigUint>> PartialOrd<BigUint> for BigUintExt<T> {
    fn partial_cmp(&self, other: &BigUint) -> Option<Ordering> {
        self.deref().partial_cmp(other)
    }
}

impl<T: Borrow<BigUint>> PartialOrd<BigUint> for &BigUintExt<T> {
    fn partial_cmp(&self, other: &BigUint) -> Option<Ordering> {
        (*self).deref().partial_cmp(other)
    }
}

impl<T: Borrow<BigUint>> Rem<BigUint> for BigUintExt<T> {
    type Output = BigUint;

    fn rem(self, rhs: BigUint) -> Self::Output {
        self.deref() % rhs
    }
}

impl<T: Borrow<BigUint>> Rem<BigUint> for &BigUintExt<T> {
    type Output = BigUint;

    fn rem(self, rhs: BigUint) -> Self::Output {
        self.deref() % rhs
    }
}

impl<T: Borrow<BigUint>> Rem<&BigUint> for BigUintExt<T> {
    type Output = BigUint;

    fn rem(self, rhs: &BigUint) -> Self::Output {
        self.deref() % rhs
    }
}

impl<T: Borrow<BigUint>> Rem<&BigUint> for &BigUintExt<T> {
    type Output = BigUint;

    fn rem(self, rhs: &BigUint) -> Self::Output {
        self.deref() % rhs
    }
}

impl<T: Borrow<BigUint>> Rem<u32> for &BigUintExt<T> {
    type Output = BigUint;

    fn rem(self, rhs: u32) -> Self::Output {
        self.deref() % rhs
    }
}

impl<T: Borrow<BigUint>> Rem<u32> for BigUintExt<T> {
    type Output = BigUint;

    fn rem(self, rhs: u32) -> Self::Output {
        self.deref() % rhs
    }
}

impl<T: Borrow<BigUint>> Sub<u32> for &BigUintExt<T> {
    type Output = BigUint;
    fn sub(self, rhs: u32) -> Self::Output {
        self.deref() - rhs
    }
}

impl<T: Borrow<BigUint>> Sub<u32> for BigUintExt<T> {
    type Output = BigUint;
    fn sub(self, rhs: u32) -> Self::Output {
        self.deref() - rhs
    }
}

impl<T: Borrow<BigUint>> Add<u32> for BigUintExt<T> {
    type Output = BigUint;
    fn add(self, rhs: u32) -> Self::Output {
        self.deref() + rhs
    }
}

impl<T: Borrow<BigUint>> Add<u32> for &BigUintExt<T> {
    type Output = BigUint;
    fn add(self, rhs: u32) -> Self::Output {
        self.deref() + rhs
    }
}

impl<T: Borrow<BigUint>> AddAssign<BigUintExt<T>> for BigUint {
    fn add_assign(&mut self, rhs: BigUintExt<T>) {
        *self += rhs.deref();
    }
}

impl<T: Borrow<BigUint>> AddAssign<&BigUintExt<T>> for BigUint {
    fn add_assign(&mut self, rhs: &BigUintExt<T>) {
        *self += rhs.deref();
    }
}

impl<T: Borrow<BigUint>> RemAssign<&BigUintExt<T>> for BigUint {
    fn rem_assign(&mut self, rhs: &BigUintExt<T>) {
        *self %= rhs.deref();
    }
}

impl<T: Borrow<BigUint>> RemAssign<BigUintExt<T>> for BigUint {
    fn rem_assign(&mut self, rhs: BigUintExt<T>) {
        *self %= rhs.deref();
    }
}

impl<T: Borrow<BigUint>> Rem<&BigUintExt<T>> for &BigUint {
    type Output = BigUint;
    fn rem(self, rhs: &BigUintExt<T>) -> Self::Output {
        self % rhs.deref()
    }
}

impl<T: Borrow<BigUint>> Rem<BigUintExt<T>> for &BigUint {
    type Output = BigUint;
    fn rem(self, rhs: BigUintExt<T>) -> Self::Output {
        self % rhs.deref()
    }
}

impl<T: Borrow<BigUint>> BigUintExt<T> {
    /// <<算法导论>>
    /// 定理31.23: 若有d=gcd(a, n), 假设对于某些整数x'和y', 有d=ax'+ny'. 如果d|b, 则方程
    /// ax=b(mod n)有一个解的值位x0, 则x0=x'(b/d) mod n;
    /// 假设方程ax=b(mod n)有解(即d|b, d=gcd(a,n)), 且x0是该方程的任意一个解. 因此, 该方程对模
    /// n恰有d个不同的解, 分别为xi=x0+i(n/d), 这里i=0,1,...,d-1;
    /// self * inv = 1 \mod modules
    pub fn modinv(&self, modulus: &BigUint) -> Option<BigUint> {
        let (a, n) = (BigInt::from(self % modulus), BigInt::from(modulus.clone()));
        let g = a.extended_gcd(&n);
        g.gcd.is_one().then_some(
            g.x.rem_euclid(&n)
                .to_biguint()
                .expect("this will always big uint"),
        )
    }

    // 生成[0..self)之间的随机数
    pub fn gen_random<R: Rand>(&self, rng: &mut R) -> BigUint {
        let bits = self.bits() as usize;
        let mut n = vec![0u8; (bits + 7) >> 3];

        loop {
            rng.rand(n.as_mut_slice());
            let r = BigUint::from_bytes_le(n.as_mut_slice());
            if self > r {
                return r;
            }
        }
    }

    /// probability prime test by the MillerRabin Pseudoprimes Algorithm and the Lucas Pseudoprimes Algorithms.
    ///
    /// n means the number of test rounds, for any odd number that great than 2 and positive integer n, the probability of error
    /// in MillerRabinPrimeTest is at most $2^{-n}$.
    pub fn probably_prime_test<Rng: Rand>(&self, test_rounds: usize, rng: &mut Rng) -> bool {
        const PRIME_BIT_MASK: u128 = 1 << 2
            | 1 << 3
            | 1 << 5
            | 1 << 7
            | 1 << 11
            | 1 << 13
            | 1 << 17
            | 1 << 19
            | 1 << 23
            | 1 << 29
            | 1 << 31
            | 1 << 37
            | 1 << 41
            | 1 << 43
            | 1 << 47
            | 1 << 53
            | 1 << 59
            | 1 << 61
            | 1 << 67
            | 1 << 71
            | 1 << 73
            | 1 << 79
            | 1 << 83
            | 1 << 89
            | 1 << 97
            | 1 << 101
            | 1 << 103
            | 1 << 107
            | 1 << 109
            | 1 << 113
            | 1 << 127;
        const PRIMES_A: u32 = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 37;
        const PRIMES_B: u32 = 29 * 31 * 41 * 43 * 47 * 53;

        if self.bits() < 8 {
            // 小素数直接判断
            if let Some(x) = self.iter_u64_digits().next() {
                return ((1 << (x as u128)) & PRIME_BIT_MASK) != 0;
            }
        } else if self.is_even() {
            return false;
        }

        let (ra, rb) = (self % PRIMES_A, self % PRIMES_B);
        let (ra, rb) = (&ra, &rb);
        if (ra % 3u32).is_zero()
            || (ra % 5u32).is_zero()
            || (ra % 7u32).is_zero()
            || (ra % 11u32).is_zero()
            || (ra % 13u32).is_zero()
            || (ra % 17u32).is_zero()
            || (ra % 19u32).is_zero()
            || (ra % 23u32).is_zero()
            || (ra % 37u32).is_zero()
            || (rb % 29u32).is_zero()
            || (rb % 31u32).is_zero()
            || (rb % 41u32).is_zero()
            || (rb % 43u32).is_zero()
            || (rb % 47u32).is_zero()
            || (rb % 53u32).is_zero()
        {
            return false;
        }

        self.prime_validate_by_miller_rabin(test_rounds + 1, rng) && self.prime_validate_by_lucas()
    }

    /// 判断`n`是否是合数, n = 2^s * r, a是在[2,n-1)之间随机选择的随机数.
    /// None表示随机数不在指定的范围内
    fn miller_rabin_witness(&self, s: usize, r: &BigUint, n_m1: &BigUint, a: &BigUint) -> bool {
        let n = self.deref();
        let mut y = a.modpow(r, n);
        let mut y2 = y.clone();

        for _ in 0..s {
            y2 *= &y;
            y2 %= n;
            if y2.is_one() && !y.is_one() && (&y != n_m1) {
                return true;
            }

            y.clone_from(&y2);
        }

        !y.is_one()
    }

    /// miller-rabin素数测试
    /// 对于任意奇数n>2和正整数t, miller-rabin素数测试出错的概率至多为2^(-t)
    ///
    /// note: 内部调用函数, self是大于2的奇数, t>0
    fn prime_validate_by_miller_rabin<Rng: Rand>(&self, t: usize, rng: &mut Rng) -> bool {
        let n_m1 = self - 1u32;
        let s = n_m1.trailing_zeros().unwrap_or(0);
        let r = &n_m1 >> s;

        for _ in 0..t {
            let a = self.gen_random(rng);
            if a.is_zero() {
                continue;
            }

            if self.miller_rabin_witness(s as usize, &r, &n_m1, &a) {
                return false;
            }
        }

        true
    }

    /// probablyPrimeLucas reports whether n passes the "almost extra strong" Lucas probable prime test,
    /// using Baillie-OEIS parameter selection. This corresponds to "AESLPSP" on Jacobsen's tables (link below).
    /// The combination of this test and a Miller-Rabin/Fermat test with base 2 gives a Baillie-PSW test.
    ///
    /// References:
    ///
    /// Baillie and Wagstaff, "Lucas Pseudoprimes", Mathematics of Computation 35(152),
    /// October 1980, pp. 1391-1417, especially page 1401.
    /// https://www.ams.org/journals/mcom/1980-35-152/S0025-5718-1980-0583518-6/S0025-5718-1980-0583518-6.pdf
    ///
    /// Grantham, "Frobenius Pseudoprimes", Mathematics of Computation 70(234),
    /// March 2000, pp. 873-891.
    /// https://www.ams.org/journals/mcom/2001-70-234/S0025-5718-00-01197-2/S0025-5718-00-01197-2.pdf
    ///
    /// Baillie, "Extra strong Lucas pseudoprimes", OEIS A217719, https://oeis.org/A217719.
    ///
    /// Jacobsen, "Pseudoprime Statistics, Tables, and Data", http://ntheory.org/pseudoprimes.html.
    ///
    /// Nicely, "The Baillie-PSW Primality Test", http://www.trnicely.net/misc/bpsw.html.
    /// (Note that Nicely's definition of the "extra strong" test gives the wrong Jacobi condition,
    /// as pointed out by Jacobsen.)
    ///
    /// Crandall and Pomerance, Prime Numbers: A Computational Perspective, 2nd ed.
    /// Springer, 2005.
    /// note: Miller-Rabin算法目前可以通过所有测试示例, 故lucas算法暂不实现
    fn prime_validate_by_lucas(&self) -> bool {
        if self.is_one() {
            return false;
        } else if self.is_even() {
            return self == BigUint::from(2u8);
        }

        // Baillie-OEIS "method C" for choosing D, P, Q,
        // as in https://oeis.org/A217719/a217719.txt:
        // try increasing P ≥ 3 such that D = P² - 4 (so Q = 1)
        // until Jacobi(D, n) = -1.
        // The search is expected to succeed for non-square n after just a few trials.
        // After more than expected failures, check whether n is square
        // (which would cause Jacobi(D, n) = 1 for all D not dividing n).
        let (mut p, n) = (3u32, BigInt::from(self.deref().clone()));
        while p <= 10000 {
            let d = BigInt::from(p * p - 4);
            let Some(j) = BigIntExt(d).jacobi(&n) else {
                return false;
            };
            if j == -1 {
                break;
            }

            if j == 0 {
                // d = p²-4 = (p-2)(p+2).
                // If (d/n) == 0 then d shares a prime factor with n.
                // Since the loop proceeds in increasing p and starts with p-2==1,
                // the shared prime factor must be p+2.
                // If p+2 == n, then n is prime; otherwise p+2 is a proper factor of n.
                if self.bits() <= 32 {
                    if let Some(x) = self.iter_u32_digits().next() {
                        return x == p + 2;
                    }
                } else {
                    return false;
                }
            }

            if p == 40 {
                // We'll never find (d/n) = -1 if n is a square.
                // If n is a non-square we expect to find a d in just a few attempts on average.
                // After 40 attempts, take a moment to check if n is indeed a square.
                let t1 = self.sqrt().pow(2u32);
                if self == t1 {
                    return false;
                }
            }

            p += 1;
        }

        // Grantham definition of "extra strong Lucas pseudoprime", after Thm 2.3 on p. 876
        // (D, P, Q above have become Δ, b, 1):
        //
        // Let U_n = U_n(b, 1), V_n = V_n(b, 1), and Δ = b²-4.
        // An extra strong Lucas pseudoprime to base b is a composite n = 2^r s + Jacobi(Δ, n),
        // where s is odd and gcd(n, 2*Δ) = 1, such that either (i) U_s ≡ 0 mod n and V_s ≡ ±2 mod n,
        // or (ii) V_{2^t s} ≡ 0 mod n for some 0 ≤ t < r-1.
        //
        // We know gcd(n, Δ) = 1 or else we'd have found Jacobi(d, n) == 0 above.
        // We know gcd(n, 2) = 1 because n is odd.
        //
        // Arrange s = (n - Jacobi(Δ, n)) / 2^r = (n+1) / 2^r.
        let (mut s, nm2) = (self + 1u32, self - 2u32);
        let r = s.trailing_zeros().unwrap_or(0);
        s >>= r;

        // We apply the "almost extra strong" test, which checks the above conditions
        // except for U_s ≡ 0 mod n, which allows us to avoid computing any U_k values.
        // Jacobsen points out that maybe we should just do the full extra strong test:
        // "It is also possible to recover U_n using Crandall and Pomerance equation 3.13:
        // U_n = D^-1 (2V_{n+1} - PV_n) allowing us to run the full extra-strong test
        // at the cost of a single modular inversion. This computation is easy and fast in GMP,
        // so we can get the full extra-strong test at essentially the same performance as the
        // almost extra strong test."

        // Compute Lucas sequence V_s(b, 1), where:
        //
        //	V(0) = 2
        //	V(1) = P
        //	V(k) = P V(k-1) - Q V(k-2).
        //
        // (Remember that due to method C above, P = b, Q = 1.)
        //
        // In general V(k) = α^k + β^k, where α and β are roots of x² - Px + Q.
        // Crandall and Pomerance (p.147) observe that for 0 ≤ j ≤ k,
        //
        //	V(j+k) = V(j)V(k) - V(k-j).
        //
        // So in particular, to quickly double the subscript:
        //
        //	V(2k) = V(k)² - 2
        //	V(2k+1) = V(k) V(k+1) - P
        //
        // We can therefore start with k=0 and build up to k=s in log₂(s) steps.
        let (mut vk1, mut vk, p) = (BigUint::from(p), BigUint::from(2u32), BigUint::from(p));
        for i in (0..=s.bits()).rev() {
            let mut t1 = &vk * &vk1;
            t1 += self;
            t1 -= &p;

            if s.bit(i) {
                // k' = 2k+1
                // V(k') = V(2k+1) = V(k) V(k+1) - P.
                vk = &t1 % self;
                // V(k'+1) = V(2k+2) = V(k+1)² - 2.
                t1 = &vk1 * &vk1;
                t1 += &nm2;
                vk1 = &t1 % self;
            } else {
                // k' = 2k
                // V(k'+1) = V(2k+1) = V(k) V(k+1) - P.
                vk1 = &t1 % self;
                // V(k') = V(2k) = V(k)² - 2
                t1 = &vk * &vk;
                t1 += &nm2;
                vk = &t1 % self;
            }
        }

        // Now k=s, so vk = V(s). Check V(s) ≡ ±2 (mod n).
        if vk == BigUint::from(2u32) || vk == nm2 {
            // Check U(s) ≡ 0.
            // As suggested by Jacobsen, apply Crandall and Pomerance equation 3.13:
            //
            //	U(k) = D⁻¹ (2 V(k+1) - P V(k))
            //
            // Since we are checking for U(k) == 0 it suffices to check 2 V(k+1) == P V(k) mod n,
            // or P V(k) - 2 V(k+1) == 0 mod n.
            let mut t1 = &vk * &p;
            t1 -= vk1 << 1;
            vk1 = &t1 % self;
            if vk1.is_zero() {
                return true;
            }
        }

        // Check V(2^t s) ≡ 0 mod n for some 0 ≤ t < r-1.
        for _ in 0..r.saturating_sub(1) {
            if vk.is_zero() {
                return true;
            }
            // Optimization: V(k) = 2 is a fixed point for V(k') = V(k)² - 2,
            // so if V(k) = 2, we can stop: we will never find a future V(k) == 0.
            if vk == BigUint::from(2u32) {
                return false;
            }
            // k' = 2k
            // V(k') = V(2k) = V(k)² - 2
            let mut t1 = &vk * &vk;
            t1 -= 2u32;
            vk = &t1 % self.deref();
        }

        false
    }

    /// generate a number p with the bits length of `bits_len`, such that p is prime
    /// with high probability that is related to the number of `test_round_num`;
    ///
    /// `test_round_num` means the number of test rounds, for any odd number that great than 2 and positive integer n, the probability of error
    /// in MillerRabinPrimeTest is at most $2^{-n}$.
    pub fn generate_prime<Rng: Rand>(
        bits_len: usize,
        test_round_num: usize,
        rng: &mut Rng,
    ) -> Result<BigUint, String> {
        if bits_len < 2 {
            return Err("prime size must at least 2-bits".to_string());
        }

        const SMALL_PRIMES: [u8; 15] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];
        const SMALL_PRIMES_PRODUCT: u64 = 16294579238595022365u64;

        let (mut p, b) = (
            vec![0u8; (bits_len + 7) >> 3],
            if (bits_len & 7) == 0 { 8 } else { bits_len & 7 },
        );
        loop {
            rng.rand(p.as_mut_slice());

            // 清除大于bits_len的位;
            if b != 8 {
                if let Some(x) = p.last_mut() {
                    *x &= (1u8 << b) - 1;
                }
            }

            // Don't let the value be too small, i.e, set the most significant two bits.
            // Setting the top two bits, rather than just the top bit,
            // means that when two of these values are multiplied together,
            // the result isn't ever one bit short.
            if b >= 2 {
                if let Some(x) = p.last_mut() {
                    *x |= 3 << (b - 2);
                }
            } else {
                for (i, x) in p.iter_mut().rev().enumerate() {
                    if i == 0 {
                        *x |= 1;
                    } else if i == 1 {
                        *x |= 0x80;
                        break;
                    }
                }
            }

            // 奇数
            if let Some(x) = p.first_mut() {
                *x |= 1;
            }

            // Calculate the value mod the product of smallPrimes. If it's
            // a multiple of any of these primes we add two until it isn't.
            // The probability of overflowing is minimal and can be ignored
            // because we still perform Miller-Rabin tests on the result.
            let mut n = BigUint::from_bytes_le(p.as_slice());
            let modulus = (&n % SMALL_PRIMES_PRODUCT)
                .to_u64()
                .expect("expect less than u64::MAX");

            'next_delta: for delta in (0u64..(1u64 << 20)).step_by(2) {
                let m = modulus + delta;
                for &prime in SMALL_PRIMES.iter() {
                    let prime = prime as u64;
                    if (m % prime) == 0 && (bits_len > 6 || m != prime) {
                        continue 'next_delta;
                    }
                }

                if delta > 0 {
                    n += delta as u32;
                }
                break;
            }

            let n = BigUintExt(n);
            if n.bits() as usize == bits_len && n.probably_prime_test(test_round_num, rng) {
                return Ok(n.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::BigUintExt;
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::DefaultRand;
    use std::time::Instant;

    #[test]
    fn gen_small_prime() {
        let mut rng = DefaultRand::default();
        let test_rounds = 19;
        for bits_len in 2..10 {
            let p = BigUintExt::<BigUint>::generate_prime(bits_len, test_rounds, &mut rng).unwrap();
            assert_eq!(p.bits() as usize, bits_len);
            assert!(BigUintExt(p).probably_prime_test(31, &mut rng));
        }
    }

    #[test]
    fn composite_validate() {
        let cases = [
            "0",
            "1",
            "21284175091214687912771199898307297748211672914763848041968395774954376176754",
            "6084766654921918907427900243509372380954290099172559290432744450051395395951",
            "84594350493221918389213352992032324280367711247940675652888030554255915464401",
            "82793403787388584738507275144194252681",

            // Arnault, "Rabin-Miller Primality Test: Composite Numbers Which Pass It",
            // Mathematics of Computation, 64(209) (January 1995), pp. 335-361.
            // strong pseudoprime to prime bases 2 through 29
            "1195068768795265792518361315725116351898245581",
            // strong pseudoprime to all prime bases up to 200
            "8038374574536394912570796143419421081388376882875581458374889175222974273765333652186502336163960045457915042023603208766569966760987284043965408232928738791850869166857328267761771029389697739470167082304286871099974399765441448453411558724506334092790222752962294149842306881685404326457534018329786111298960644845216191652872597534901",

            // Extra-strong Lucas pseudoprimes. https://oeis.org/A217719
            "989",
            "3239",
            "5777",
            "10877",
            "27971",
            "29681",
            "30739",
            "31631",
            "39059",
            "72389",
            "73919",
            "75077",
            "100127",
            "113573",
            "125249",
            "137549",
            "137801",
            "153931",
            "155819",
            "161027",
            "162133",
            "189419",
            "218321",
            "231703",
            "249331",
            "370229",
            "429479",
            "430127",
            "459191",
            "473891",
            "480689",
            "600059",
            "621781",
            "632249",
            "635627",

            "3673744903",
            "3281593591",
            "2385076987",
            "2738053141",
            "2009621503",
            "1502682721",
            "255866131",
            "117987841",
            "587861",

            "6368689",
            "8725753",
            "80579735209",
            "105919633",
        ];

        let (test_rounds, mut rng) = (10, DefaultRand::default());
        for s in cases {
            let composite =
                BigUint::from_str_radix(s, 10).expect("convert string to big uint failed");
            let t = Instant::now();
            assert!(
                !BigUintExt(composite).probably_prime_test(test_rounds, &mut rng),
                "composite `{}` test failed",
                s
            );
            println!(
                "probably prime time elapsed `{:?}` for the composite `{}`",
                t.elapsed(),
                s
            );
        }
    }

    #[test]
    fn prime_validate() {
        let cases = [
            "13756265695458089029",
            "2",
            "3",
            "5",
            "7",
            "11",
            "13496181268022124907",
            "10953742525620032441",
            "17908251027575790097",

            // https://golang.org/issue/638
            "18699199384836356663",

            "98920366548084643601728869055592650835572950932266967461790948584315647051443",
            "94560208308847015747498523884063394671606671904944666360068158221458669711639",

            // https://primes.utm.edu/lists/small/small3.html
            "449417999055441493994709297093108513015373787049558499205492347871729927573118262811508386655998299074566974373711472560655026288668094291699357843464363003144674940345912431129144354948751003607115263071543163",
            "230975859993204150666423538988557839555560243929065415434980904258310530753006723857139742334640122533598517597674807096648905501653461687601339782814316124971547968912893214002992086353183070342498989426570593",
            "5521712099665906221540423207019333379125265462121169655563495403888449493493629943498064604536961775110765377745550377067893607246020694972959780839151452457728855382113555867743022746090187341871655890805971735385789993",
            "203956878356401977405765866929034577280193993314348263094772646453283062722701277632936616063144088173312372882677123879538709400158306567338328279154499698366071906766440037074217117805690872792848149112022286332144876183376326512083574821647933992961249917319836219304274280243803104015000563790123",

            // ECC primes: https://tools.ietf.org/html/draft-ladd-safecurves-02
            "3618502788666131106986593281521497120414687020801267626233049500247285301239",                                                                                  // Curve1174: 2^251-9
            "57896044618658097711785492504343953926634992332820282019728792003956564819949",                                                                                 // Curve25519: 2^255-19
            "9850501549098619803069760025035903451269934817616361666987073351061430442874302652853566563721228910201656997576599",                                           // E-382: 2^382-105
            "42307582002575910332922579714097346549017899709713998034217522897561970639123926132812109468141778230245837569601494931472367",                                 // Curve41417: 2^414-17
            "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", // E-521: 2^521-1
        ];

        let (test_rounds, mut rng) = (10usize, DefaultRand::default());
        for s in cases {
            let prime = BigUint::from_str_radix(s, 10).expect("convert string to big uint failed");
            let n = BigUintExt(prime);
            let t = Instant::now();
            assert!(
                n.probably_prime_test(test_rounds, &mut rng),
                "prime `{}` test failed",
                s
            );
            println!(
                "probably prime time elapsed `{:?}` for the prime `{}`",
                t.elapsed(),
                s
            );
        }
    }
}
