use ark_ec::{
    twisted_edwards::{
        Affine as ArkAffine, MontCurveConfig, Projective as ArkProjective, TECurveConfig,
    },
    CurveConfig,
};
use ark_ff::{Fp256, MontBackend, MontConfig, MontFp};

#[derive(MontConfig)]
#[modulus = "57896044618658097711785492504343953926634992332820282019728792003956564819949"]
#[generator = "2"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

#[derive(MontConfig)]
#[modulus = "7237005577332262213973186563042994240857116359379907606001950938285454250989"]
#[generator = "2"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Config;

pub type Affine = ArkAffine<Config>;
pub type Projective = ArkProjective<Config>;

impl CurveConfig for Config {
    const COFACTOR: &'static [u64] = &[0x8];

    // 8^(-1) mod r
    const COFACTOR_INV: Self::ScalarField =
        MontFp!("2713877091499598330239944961141122840321418634767465352250731601857045344121");

    type BaseField = Fq;

    type ScalarField = Fr;
}

// Edwards:
const G_X: Fq =
    MontFp!("15112221349535400772501151409588531511454012693041857206046113283949847762202");
// 4/5
const G_Y: Fq =
    MontFp!("46316835694926478169428394003475163141307993866256225615783033603165251855960");

impl TECurveConfig for Config {
    // -1
    const COEFF_A: Self::BaseField =
        MontFp!("57896044618658097711785492504343953926634992332820282019728792003956564819948");
    // -121665/121666
    const COEFF_D: Self::BaseField =
        MontFp!("37095705934669439343138083508754565189542113879843219016388785533085940283555");
    const GENERATOR: ArkAffine<Self> = ArkAffine::new_unchecked(G_X, G_Y);
    type MontCurveConfig = Config;
}

impl MontCurveConfig for Config {
    const COEFF_A: Self::BaseField = MontFp!("486662");
    const COEFF_B: Self::BaseField =
        MontFp!("57896044618658097711785492504343953926634992332820282019728792003956564333285");
    type TECurveConfig = Config;
}
