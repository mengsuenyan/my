use crate::cmd::crypto::ae::{CCMArgs, GCMArgs};
use crate::cmd::crypto::block::BlockCipherType;
use crate::cmd::crypto::mode::{CBCArgs, CBCCSArgs, CFBArgs, CTRArgs, ECBArgs, OFBArgs};
use crate::cmd::crypto::rsa::{OAEPArgs, PKCS1Args};
use crate::cmd::crypto::zuc::ZUCArgs;
use crate::cmd::hash::HashSubCmd;
use crate::cmd::kdf::KDFSubArgs;

pub trait Info {
    fn name(&self) -> String;

    fn merge_name<T: Info>(&self, another: &T) -> String {
        let (mut l, r) = (self.name(), another.name());
        l.push('/');
        l.push_str(r.as_str());
        l
    }
}

impl Info for HashSubCmd {
    fn name(&self) -> String {
        match self {
            HashSubCmd::SM3(_) => "SM3",
            HashSubCmd::SHA1(_) => "SHA1",
            HashSubCmd::SHA2_224(_) => "SHA2-224",
            HashSubCmd::SHA2_256(_) => "SHA2-256",
            HashSubCmd::SHA2_384(_) => "SHA2-384",
            HashSubCmd::SHA2_512(_) => "SHA2-512",
            HashSubCmd::SHA2_512T224(_) => "SHA2-512T224",
            HashSubCmd::SHA2_512T256(_) => "SHA2-512T256",
            HashSubCmd::SHA2_512T(_) => "SHA2-512t",
            HashSubCmd::SHA3_224(_) => "SHA3-224",
            HashSubCmd::SHA3_256(_) => "SHA3-256",
            HashSubCmd::SHA3_384(_) => "SHA3-384",
            HashSubCmd::SHA3_512(_) => "SHA3-512",
            HashSubCmd::SHAKE128(_) => "SHAKE128",
            HashSubCmd::SHAKE256(_) => "SHAKE256",
            HashSubCmd::RawSHAKE128(_) => "RawSHAKE128",
            HashSubCmd::RawSHAKE256(_) => "RawSHAKE256",
            HashSubCmd::CSHAKE128(_) => "CSHAKE128",
            HashSubCmd::CSHAKE256(_) => "CSHAKE256",
            HashSubCmd::KMACXof128(_) => "KMACXof128",
            HashSubCmd::KMACXof256(_) => "KMACXof256",
            HashSubCmd::KMAC128(_) => "KMAC128",
            HashSubCmd::KMAC256(_) => "KMAC256",
            HashSubCmd::BLAKE2b128(_) => "BLAKE2b128",
            HashSubCmd::BLAKE2b224(_) => "BLAKE2b224",
            HashSubCmd::BLAKE2b256(_) => "BLAKE2b256",
            HashSubCmd::BLAKE2b384(_) => "BLAKE2b384",
            HashSubCmd::BLAKE2b512(_) => "BLAKE2b512",
            HashSubCmd::BLAKE2s128(_) => "BLAKE2s128",
            HashSubCmd::BLAKE2s224(_) => "BLAKE2s224",
            HashSubCmd::BLAKE2s256(_) => "BLAKE2s256",
            HashSubCmd::BLAKE2b(_) => "BLAKE2b",
            HashSubCmd::BLAKE2s(_) => "BLAKE2s",
        }
        .to_string()
    }
}

impl Info for KDFSubArgs {
    fn name(&self) -> String {
        match self {
            KDFSubArgs::Plain(a) => {
                if let Some(h) = a.h.as_ref() {
                    format!("plain/{}", h.name())
                } else {
                    "plain".to_string()
                }
            }
            KDFSubArgs::PBKDF1(a) => format!("pbkdf1/{}", a.h.name()),
            KDFSubArgs::PBKDF2(a) => format!("pbkdf2/{}", a.h.name()),
            KDFSubArgs::Scrypt(_) => "scrypt".to_string(),
            KDFSubArgs::Argon2(_) => "argon2".to_string(),
            KDFSubArgs::RSA(_) => "rsa".to_string(),
        }
    }
}

impl Info for BlockCipherType {
    fn name(&self) -> String {
        match self {
            BlockCipherType::SM4 => "SM4".to_string(),
            BlockCipherType::AES128 => "AES128".to_string(),
            BlockCipherType::AES192 => "AES192".to_string(),
            BlockCipherType::AES256 => "AES256".to_string(),
        }
    }
}

impl Info for ECBArgs {
    fn name(&self) -> String {
        "ECB".to_string()
    }
}

impl Info for CBCArgs {
    fn name(&self) -> String {
        "CBC".to_string()
    }
}

impl Info for CFBArgs {
    fn name(&self) -> String {
        "CFB".to_string()
    }
}

impl Info for OFBArgs {
    fn name(&self) -> String {
        "OFB".to_string()
    }
}

impl Info for CTRArgs {
    fn name(&self) -> String {
        "CTR".to_string()
    }
}

impl Info for CBCCSArgs {
    fn name(&self) -> String {
        "CBCCS".to_string()
    }
}

impl Info for ZUCArgs {
    fn name(&self) -> String {
        "ZUC".to_string()
    }
}

impl Info for CCMArgs {
    fn name(&self) -> String {
        "CCM".to_string()
    }
}

impl Info for GCMArgs {
    fn name(&self) -> String {
        "GCM".to_string()
    }
}

impl Info for OAEPArgs {
    fn name(&self) -> String {
        "RSA-OAEP".to_string()
    }
}

impl Info for PKCS1Args {
    fn name(&self) -> String {
        "RSA-PKCS1".to_string()
    }
}

impl Info for String {
    fn name(&self) -> String {
        self.clone()
    }
}
