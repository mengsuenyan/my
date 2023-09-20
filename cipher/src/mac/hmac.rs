//! The Keyed-Hash Message Authentication Code (HMAC) <br>
//!
//! - [FIPS 198-1 HMAC](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf) <br>
//!
//! - MAC(text) = HMAC(K, text) = H((K0 ⊕ opad )|| H((K0 ⊕ ipad) || text))
//!

use crate::{CipherError, MAC};
use crypto_hash::Digest;
use std::cmp::Ordering;
use std::io::Write;
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

pub struct HMAC<D> {
    k0_i: Vec<u8>,
    k0_o: Vec<u8>,
    pre_mac: Vec<u8>,
    digest: D,
    is_finalize: bool,
}

impl<D> HMAC<D> {
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;
}

impl<D: Digest> HMAC<D> {
    pub fn new(mut digest: D, key: Vec<u8>) -> Result<Self, CipherError> {
        if D::BLOCK_BITS < D::DIGEST_BITS {
            // key.len() > BLOCK_SIZE时需要哈希生成k0
            return Err(CipherError::Other(format!(
                "{} doesn't satisfies to block bits great than digest bits.",
                std::any::type_name::<D>()
            )));
        }

        let mut k0_i = Self::k0(key, (D::BLOCK_BITS + 7) >> 3);
        let mut k0_o = k0_i.clone();
        k0_i.iter_mut().for_each(|x| {
            *x ^= Self::IPAD;
        });
        k0_o.iter_mut().for_each(|x| {
            *x ^= Self::OPAD;
        });

        digest
            .write_all(k0_i.as_slice())
            .map_err(CipherError::from)?;

        Ok(Self {
            pre_mac: vec![],
            k0_i,
            k0_o,
            digest,
            is_finalize: false,
        })
    }

    fn k0(mut key: Vec<u8>, block_size: usize) -> Vec<u8> {
        match key.len().cmp(&block_size) {
            Ordering::Less => {
                key.resize(block_size, 0);
                key
            }
            Ordering::Equal => key,
            Ordering::Greater => {
                let mut k0: Vec<_> = D::digest(key.as_slice()).into();
                k0.resize(block_size, 0);
                #[cfg(feature = "sec-zeroize")]
                key.zeroize();
                k0
            }
        }
    }
}

#[cfg(feature = "sec-zeroize")]
impl<D> Zeroize for HMAC<D> {
    fn zeroize(&mut self) {
        self.k0_o.zeroize();
        self.k0_i.zeroize();
        self.pre_mac.zeroize();
    }
}

impl<D: Clone> Clone for HMAC<D> {
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
            k0_i: self.k0_i.clone(),
            k0_o: self.k0_o.clone(),
            pre_mac: self.pre_mac.clone(),
            is_finalize: self.is_finalize,
        }
    }
}

impl<D: Digest + Clone> Write for HMAC<D> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.is_finalize {
            self.reset();
        }

        self.digest.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if self.is_finalize {
            self.reset();
        }

        self.digest.write_all(buf)
    }
}

impl<D: Digest + Clone> MAC for HMAC<D> {
    const BLOCK_SIZE: usize = (D::BLOCK_BITS + 7) >> 3;
    const DIGEST_SIZE: usize = (D::DIGEST_BITS + 7) >> 3;

    fn mac(&mut self) -> Vec<u8> {
        if self.is_finalize {
            return self.pre_mac.clone();
        }

        let mut h1: Vec<_> = self.digest.clone().finalize().into();
        self.digest.reset();
        h1.extend(self.k0_o.iter());
        h1.rotate_right(self.k0_o.len());

        let out: Vec<_> = D::digest(h1.as_slice()).into();
        self.pre_mac.clear();
        self.pre_mac.extend(out.iter());
        #[cfg(feature = "sec-zeroize")]
        h1.zeroize();

        self.is_finalize = true;
        out
    }

    fn reset(&mut self) {
        self.digest.reset();
        self.pre_mac.clear();
        self.is_finalize = false;
    }
}

#[cfg(test)]
mod tests {
    use crate::mac::HMAC;
    use crate::MAC;
    use crypto_hash::sha2::{SHA1, SHA224, SHA256, SHA384, SHA512};
    use num_bigint::BigUint;
    use num_traits::Num;
    use std::io::Write;

    #[test]
    fn hmac_sha1() {
        // (hash, text, key)
        let cases = [
            (
                "4f4ca3d5d68ba7cc0a1208c9c61e9c5da0403c0a",
                "Sample #1",
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
            ),
            (
                "0922d3405faa3d194f82a45830737d5cc6c75d24",
                "Sample #2",
                vec![
                    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
                    0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43,
                ],
            ),
            (
                "bcf41eab8bb2d802f3d05caf7cb092ecf8d1a3aa",
                "Sample #3",
                vec![
                    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
                    0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
                    0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
                    0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
                    0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
                    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
                    0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
                    0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
                ],
            ),
            (
                "5fd596ee78d5553c8ff4e72d266dfd192366da29",
                "Sample message for keylen=blocklen",
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
            ),
            (
                "4c99ff0cb1b31bd33f8431dbaf4d17fcd356a807",
                "Sample message for keylen<blocklen",
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
                ],
            ),
            (
                "2d51b2f7750e410584662e38f133435f4c4fd42a",
                "Sample message for keylen=blocklen",
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
                    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                    0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
                    0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
                ],
            ),
        ];

        for (i, (mac, txt, key)) in cases.into_iter().enumerate() {
            let mac = BigUint::from_str_radix(mac, 16).unwrap().to_bytes_be();
            let mut hmac = HMAC::new(SHA1::new(), key).unwrap();
            hmac.write_all(txt.as_bytes()).unwrap();
            let tgt = hmac.mac();
            assert_eq!(tgt, mac, "case {i} hmac({}) failed", txt);
        }
    }

    #[test]
    fn hmac_sha256() {
        // (hash, text, key)
        let cases = [
            ("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "Hi There".as_bytes().to_vec(), vec![0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                                                                                                      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                                                                                                      0x0b, 0x0b, 0x0b, 0x0b,]),
            ("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "what do ya want for nothing?".as_bytes().to_vec(), vec![74, 101, 102, 101]),
            ("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", vec![0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                                                                                      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                                                                                      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                                                                                      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                                                                                      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                                                                                      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                                                                                      0xdd, 0xdd,], vec![0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                         0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                         0xaa, 0xaa, 0xaa, 0xaa,]),
            ("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", vec![0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                                                                                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                                                                                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                                                                                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                                                                                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                                                                                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                                                                                      0xcd, 0xcd,], vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                                                                                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                                                                                                         0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                                                                                         0x19,]),
            ("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes().to_vec(), vec![0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                                                                                                                                                                    0xaa, 0xaa, 0xaa,]),
            ("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
             "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".as_bytes().to_vec(),
             vec![0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                  0xaa, 0xaa, 0xaa,]),
            ("8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62", "Sample message for keylen=blocklen".as_bytes().to_vec(), vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                                                                                                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                                                                                                                                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                                                                                                                                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                                                                                                                                                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                                                                                                                                                0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                                                                                                                                                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                                                                                                                                0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,]),
            ("a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790", "Sample message for keylen<blocklen".as_bytes().to_vec(), vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                                                                                                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                                                                                                                                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                                                                                                                                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,]),
            ("bdccb6c72ddeadb500ae768386cb38cc41c63dbb0878ddb9c7a38a431b78378d", "Sample message for keylen=blocklen".as_bytes().to_vec(), vec![			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                                                                                                                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                                                                                                                                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                                                                                                                                            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                                                                                                                                                            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                                                                                                                                                            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                                                                                                                                                            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                                                                                                                                            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                                                                                                                                                            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                                                                                                                                                            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                                                                                                                                                            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                                                                                                                                                            0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                                                                                                                                                            0x60, 0x61, 0x62, 0x63,
            ]),
        ];

        for (i, (mac, txt, key)) in cases.into_iter().enumerate() {
            let mac = BigUint::from_str_radix(mac, 16).unwrap().to_bytes_be();
            let mut hmac = HMAC::new(SHA256::new(), key).unwrap();
            hmac.write_all(txt.as_slice()).unwrap();
            let tgt = hmac.mac();
            assert_eq!(tgt, mac, "case {i} hmac(txt) failed");
            assert_eq!(hmac.mac(), mac, "case {i} hmac(txt) failed");
        }
    }

    #[test]
    fn hmac_sha224() {
        let cases = [
            (
                "c7405e3ae058e8cd30b08b4140248581ed174cb34e1224bcc1efc81b",
                "Sample message for keylen=blocklen".as_bytes().to_vec(),
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
            ),
            (
                "e3d249a8cfb67ef8b7a169e9a0a599714a2cecba65999a51beb8fbbe",
                "Sample message for keylen<blocklen".as_bytes().to_vec(),
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b,
                ],
            ),
            (
                "91c52509e5af8531601ae6230099d90bef88aaefb961f4080abc014d",
                "Sample message for keylen=blocklen".as_bytes().to_vec(),
                vec![
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
                    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                    0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
                    0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
                ],
            ),
        ];

        for (i, (mac, txt, key)) in cases.into_iter().enumerate() {
            let mac = BigUint::from_str_radix(mac, 16).unwrap().to_bytes_be();
            let mut hmac = HMAC::new(SHA224::new(), key).unwrap();
            hmac.write_all(txt.as_slice()).unwrap();
            let tgt = hmac.mac();
            assert_eq!(tgt, mac, "case {i} hmac(txt) failed");
        }
    }

    #[test]
    fn hmac_sha384() {
        let cases = [
            ("63c5daa5e651847ca897c95814ab830bededc7d25e83eef9195cd45857a37f448947858f5af50cc2b1b730ddf29671a9",
             "Sample message for keylen=blocklen".as_bytes().to_vec(),
             vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                  0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                  0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
                  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                  0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,]),
            ("6eb242bdbb582ca17bebfa481b1e23211464d2b7f8c20b9ff2201637b93646af5ae9ac316e98db45d9cae773675eeed0",
             "Sample message for keylen<blocklen".as_bytes().to_vec(),
             vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,]),
            ("5b664436df69b0ca22551231a3f0a3d5b4f97991713cfa84bff4d0792eff96c27dccbbb6f79b65d548b40e8564cef594",
             "Sample message for keylen=blocklen".as_bytes().to_vec(),
             vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                  0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                  0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
                  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                  0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
                  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
                  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
                  0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
                  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,]),
        ];

        for (i, (mac, txt, key)) in cases.into_iter().enumerate() {
            let mac = BigUint::from_str_radix(mac, 16).unwrap().to_bytes_be();
            let mut hmac = HMAC::new(SHA384::new(), key).unwrap();
            hmac.write_all(txt.as_slice()).unwrap();
            let tgt = hmac.mac();
            assert_eq!(tgt, mac, "case {i} hmac(txt) failed");
        }
    }

    #[test]
    fn hmac_sha512() {
        let cases = [
            ("fc25e240658ca785b7a811a8d3f7b4ca48cfa26a8a366bf2cd1f836b05fcb024bd36853081811d6cea4216ebad79da1cfcb95ea4586b8a0ce356596a55fb1347",
             "Sample message for keylen=blocklen".as_bytes().to_vec(),
             vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                  0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                  0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
                  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                  0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,]),
            ("fd44c18bda0bb0a6ce0e82b031bf2818f6539bd56ec00bdc10a8a2d730b3634de2545d639b0f2cf710d0692c72a1896f1f211c2b922d1a96c392e07e7ea9fedc",
             "Sample message for keylen<blocklen".as_bytes().to_vec(),
             vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,]),
            ("d93ec8d2de1ad2a9957cb9b83f14e76ad6b5e0cce285079a127d3b14bccb7aa7286d4ac0d4ce64215f2bc9e6870b33d97438be4aaa20cda5c5a912b48b8e27f3",
             "Sample message for keylen=blocklen".as_bytes().to_vec(),
             vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
                  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                  0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                  0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
                  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                  0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
                  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
                  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
                  0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
                  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,]),
        ];

        for (i, (mac, txt, key)) in cases.into_iter().enumerate() {
            let mac = BigUint::from_str_radix(mac, 16).unwrap().to_bytes_be();
            let mut hmac = HMAC::new(SHA512::new(), key).unwrap();
            hmac.write_all(txt.as_slice()).unwrap();
            let tgt = hmac.mac();
            assert_eq!(tgt, mac, "case {i} hmac(txt) failed");
        }
    }
}
