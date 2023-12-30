use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Euclid, One, Signed, Zero};
use std::borrow::Borrow;
use std::ops::Deref;

pub struct BigIntExt<T: Borrow<BigInt>>(pub T);

impl<T: Borrow<BigInt>> Deref for BigIntExt<T> {
    type Target = BigInt;
    fn deref(&self) -> &Self::Target {
        self.0.borrow()
    }
}

impl<T: Borrow<BigInt>> BigIntExt<T> {
    /// <<算法导论>>
    /// 定理31.23: 若有d=gcd(a, n), 假设对于某些整数x'和y', 有d=ax'+ny'. 如果d|b, 则方程
    /// ax=b(mod n)有一个解的值位x0, 则x0=x'(b/d) mod n;
    /// 假设方程ax=b(mod n)有解(即d|b, d=gcd(a,n)), 且x0是该方程的任意一个解. 因此, 该方程对模
    /// n恰有d个不同的解, 分别为xi=x0+i(n/d), 这里i=0,1,...,d-1;
    /// self * inv = 1 \mod modules.abs()
    ///
    pub fn modinv(&self, modulus: &BigInt) -> Option<BigInt> {
        let n = modulus.abs();
        let a = self.rem_euclid(&n);
        let g = a.extended_gcd(&n);
        g.gcd.is_one().then_some(g.x.rem_euclid(&n))
    }

    /// compute the Jacobi symbol $(\frac{self}{b})$, returned None if the self == nan, b == nan or b == 0
    pub fn jacobi(&self, b: &BigInt) -> Option<isize> {
        if b.is_zero() {
            return None;
        }

        let (mut a, mut b) = (self.deref().clone(), b.clone());

        let mut j = if b.is_negative() {
            b = -b;
            if a.is_negative() {
                -1
            } else {
                1
            }
        } else {
            1
        };

        let (three, five, seven) = (BigInt::from(3u8), BigInt::from(5u8), BigInt::from(7u8));
        loop {
            if b.is_one() {
                return Some(j);
            }

            if a.is_zero() {
                return Some(0);
            }

            a = a.rem_euclid(&b);
            if a.is_zero() {
                return Some(0);
            }

            let s = a.trailing_zeros().unwrap_or(0);
            if (s & 1) != 0 {
                let bmod8 = &b & &seven;
                if bmod8 == three || bmod8 == five {
                    j = -j;
                }
            }

            a >>= s;
            if (&b & &three) == three && (&a & &three) == three {
                j = -j;
            }

            (a, b) = (b, a);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::bigint_ext::BigIntExt;
    use num_bigint::BigInt;
    use num_traits::{Euclid, Num, One, Signed};

    #[test]
    fn jacobi() {
        // (x,y,out)
        let cases = [
            (0, 1i128, 1),
            (0, -1, 1),
            (1, 1, 1),
            (1, -1, 1),
            (0, 5, 0),
            (1, 5, 1),
            (2, 5, -1),
            (-2, 5, -1),
            (2, -5, -1),
            (-2, -5, 1),
            (3, 5, -1),
            (5, 5, 0),
            (-5, 5, 0),
            (6, 5, 1),
            (6, -5, 1),
            (-6, 5, 1),
            (-6, -5, -1),
            (5, 13756265695458089029, 1),
            (12, 13756265695458089029, 1),
        ];

        cases.iter().for_each(|e| {
            let x = BigIntExt(BigInt::from(e.0));
            let y = BigInt::from(e.1);
            let out = Some(e.2);
            let j = x.jacobi(&y);
            assert_eq!(j, out, "case: jacobi({}, {})", x.0, y);
        });
    }

    #[test]
    fn mod_inv() {
        // the test cases come from the int_test.go in the golang source code
        let cases = [
            ("1234567", "458948883992"),
            ("239487239847", "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919"),
            ("-10", "13"), // issue #16984
            ("10", "-13"),
            ("-17", "-13"),
        ];

        for case in cases {
            let (a, n) = (
                BigInt::from_str_radix(case.0, 10).expect("can't convert str to big int"),
                BigInt::from_str_radix(case.1, 10).expect("can't convert str to big int"),
            );

            let nr = n.abs();
            let ar = a.rem_euclid(&nr);
            let inv = BigIntExt(a).modinv(&n).expect("inverse exist");
            let one = (ar * &inv) % nr;
            assert!(one.is_one(), "{} * {} != 1 % n", case.0, inv);
        }
    }
}
