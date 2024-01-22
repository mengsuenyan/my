use ark_ec::{
    twisted_edwards::{
        Affine as ArkAffine, MontCurveConfig, Projective as ArkProjective, TECurveConfig,
    },
    CurveConfig,
};
use ark_ff::{Fp448, MontBackend, MontConfig, MontFp};

#[derive(MontConfig)]
#[modulus = "726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439"]
#[generator = "7"]
pub struct FqConfig;
pub type Fq = Fp448<MontBackend<FqConfig, 7>>;

#[derive(MontConfig)]
#[modulus = "181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779"]
#[generator = "2"]
pub struct FrConfig;
pub type Fr = Fp448<MontBackend<FrConfig, 7>>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Config;

pub type Affine = ArkAffine<Config>;
pub type Projective = ArkProjective<Config>;

impl CurveConfig for Config {
    const COFACTOR: &'static [u64] = &[4];

    // 8^(-1) mod r
    const COFACTOR_INV: Self::ScalarField = MontFp!("45427420268475430659332737993000283397102585042957378767593137448786500990384896429048938822923093990827573427272915576193438964912445");

    type BaseField = Fq;

    type ScalarField = Fr;
}

// Montgemory:
// u=5
// v=355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362
// Edwards:
const G_X: Fq = MontFp!("587918410962902615694256343270129103678215722007944325728614969032968498356220193850703644182647611533995834554907122492158700931984129");
const G_Y: Fq = MontFp!("484559149530404593699549205258669689569094240458212040187660132787074885444487181790930922465784363953392589641229091574035665345576960");

impl TECurveConfig for Config {
    const COEFF_A: Self::BaseField = MontFp!("156328");
    const COEFF_D: Self::BaseField = MontFp!("156324");
    const GENERATOR: ArkAffine<Self> = ArkAffine::new_unchecked(G_X, G_Y);
    type MontCurveConfig = Config;
}

impl MontCurveConfig for Config {
    const COEFF_A: Self::BaseField = MontFp!("156326");
    const COEFF_B: Self::BaseField = MontFp!("1");
    type TECurveConfig = Config;
}
