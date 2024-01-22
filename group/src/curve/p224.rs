use ark_ec::{
    short_weierstrass::{Affine as ArkAffine, Projective as ArkProjective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{Field, Fp256, MontBackend, MontConfig, MontFp};

#[derive(MontConfig)]
#[modulus = "26959946667150639794667015087019630673557916260026308143510066298881"]
#[generator = "11"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

#[derive(MontConfig)]
#[modulus = "26959946667150639794667015087019625940457807714424391721682722368061"]
#[generator = "2"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Config;

pub type Affine = ArkAffine<Config>;
pub type Projective = ArkProjective<Config>;

impl CurveConfig for Config {
    type BaseField = Fq;
    type ScalarField = Fr;

    const COFACTOR: &'static [u64] = &[0x1];

    const COFACTOR_INV: Fr = Fr::ONE;
}

const GENERATOR_X: Fq =
    MontFp!("19277929113566293071110308034699488026831934219452440156649784352033");
const GENERATOR_Y: Fq =
    MontFp!("19926808758034470970197974370888749184205991990603949537637343198772");

impl SWCurveConfig for Config {
    /// -3
    const COEFF_A: Self::BaseField =
        MontFp!("26959946667150639794667015087019630673557916260026308143510066298878");
    const COEFF_B: Self::BaseField =
        MontFp!("18958286285566608000408668544493926415504680968679321075787234672564");
    const GENERATOR: ark_ec::short_weierstrass::Affine<Self> =
        ArkAffine::new_unchecked(GENERATOR_X, GENERATOR_Y);
}

#[cfg(test)]
mod tests {
    use super::Fq;
    use ark_ff::{BigInteger, PrimeField};
    use num_traits::{One, Zero};

    #[test]
    fn fq() {
        let (zero, one) = (Fq::zero(), Fq::one());
        let mut p_1 = <Fq as PrimeField>::MODULUS;
        let _ = p_1.sub_with_borrow(&<Fq as PrimeField>::BigInt::from(1u8));
        let p_1 = <Fq as PrimeField>::from_bigint(p_1).unwrap();
        let x = zero - one;
        assert_eq!(x, p_1);
        assert_eq!(one, p_1 * p_1);
    }
}
