use ark_ec::{
    short_weierstrass::{Affine as ArkAffine, Projective as ArkProjective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{Field, Fp384, MontBackend, MontConfig, MontFp};

#[derive(MontConfig)]
#[modulus = "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319"]
#[generator = "19"]
pub struct FqConfig;
pub type Fq = Fp384<MontBackend<FqConfig, 6>>;

#[derive(MontConfig)]
#[modulus = "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643"]
#[generator = "2"]
pub struct FrConfig;
pub type Fr = Fp384<MontBackend<FrConfig, 6>>;

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

const G_X: Fq = MontFp!("26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087");
const G_Y: Fq = MontFp!("8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871");

impl SWCurveConfig for Config {
    // -3
    const COEFF_A: Self::BaseField = MontFp!("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316");
    const COEFF_B: Self::BaseField = MontFp!("27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575");
    const GENERATOR: ark_ec::short_weierstrass::Affine<Self> = ArkAffine::new_unchecked(G_X, G_Y);
}
