use ark_ec::{
    short_weierstrass::{Affine as ArkAffine, Projective as ArkProjective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{Field, Fp256, MontBackend, MontConfig, MontFp};

#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573530086143415290314195533631308867097853951"]
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573529996955224135760342422259061068512044369"]
#[generator = "7"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Config;
pub type Affine = ArkAffine<Config>;
pub type Projective = ArkProjective<Config>;

impl CurveConfig for Config {
    const COFACTOR: &'static [u64] = &[0x1];
    const COFACTOR_INV: Self::ScalarField = Fr::ONE;
    type BaseField = Fq;
    type ScalarField = Fr;
}

const G_X: Fq =
    MontFp!("48439561293906451759052585252797914202762949526041747995844080717082404635286");
const G_Y: Fq =
    MontFp!("36134250956749795798585127919587881956611106672985015071877198253568414405109");

impl SWCurveConfig for Config {
    // -3
    const COEFF_A: Self::BaseField =
        MontFp!("115792089210356248762697446949407573530086143415290314195533631308867097853948");
    const COEFF_B: Self::BaseField =
        MontFp!("41058363725152142129326129780047268409114441015993725554835256314039467401291");
    const GENERATOR: ark_ec::short_weierstrass::Affine<Self> = ArkAffine::new_unchecked(G_X, G_Y);
}
