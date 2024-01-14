//! RSA
//!
//! - 随机选择两个质数$p$和$q$($p\neq q$), 则模数$n=p*q$. 模数的字节长度$k$满足: $2^{((k-1)*8}\le n \lt 2^{k*8}$;
//! - 在$[1,n]$之中, 随机选择一个整数$e$作为公钥的指数部分. 其中, $e$满足和$p-1$及$q-1$都是互质关系(公共因子是1);
//! - 那么私钥的指数部分$d$满足: $d*e-1$能被$q-1$和$p-1$整除;
//!
//! 加密: $y = x ^ e \mod n$;
//!
//! 解密: $y = x^d \mod n$;
//!
//! 原理: 欧拉定理$a^{\phi(n)} \equiv 1 \mod n$
//! - $x ^ {k(p-1)(q-1)+1} \equiv x \mod n$
//!
//!

mod key;

pub use key::{PrivateKey, PublicKey};

mod oaep;
pub use oaep::{OAEPDecrypt, OAEPEncrypt};

mod stream;
pub use stream::{OAEPDecryptStream, OAEPEncryptStream, PKCS1DecryptStream, PKCS1EncryptStream};

mod flag;
use flag::FlagClear;

mod pkcs1;
pub use pkcs1::{PKCS1Decrypt, PKCS1Encrypt};

mod pss;
pub use pss::{PSSSign, PSSVerify};
