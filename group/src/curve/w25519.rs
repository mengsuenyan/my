use ark_ec::{
    short_weierstrass::{Affine as ArkAffine, Projective as ArkProjective, SWCurveConfig},
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

const G_X: Fq =
    MontFp!("19298681539552699237261830834781317975544997444273427339909597334652188435546");
const G_Y: Fq =
    MontFp!("43114425171068552920764898935933967039370386198203806730763910166200978582548");

impl SWCurveConfig for Config {
    const COEFF_A: Self::BaseField =
        MontFp!("19298681539552699237261830834781317975544997444273427339909597334573241639236");
    const COEFF_B: Self::BaseField =
        MontFp!("55751746669818908907645289078257140818241103727901012315294400837956729358436");
    const GENERATOR: ArkAffine<Self> = ArkAffine::new_unchecked(G_X, G_Y);
}
