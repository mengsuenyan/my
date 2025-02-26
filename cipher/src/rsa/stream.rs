use crate::rsa::{OAEPDecrypt, OAEPEncrypt, PKCS1Decrypt, PKCS1Encrypt};
use crate::{CipherError, Rand, StreamCipherFinish, StreamDecrypt, StreamEncrypt};
use crypto_hash::DigestX;
use std::io::{Read, Write};
use std::ops::Deref;

pub struct OAEPEncryptStream<H: DigestX, R: Rand> {
    buf: Vec<u8>,
    oaep: OAEPEncrypt<H, R>,
}

pub struct OAEPDecryptStream<H: DigestX, R: Rand> {
    buf: Vec<u8>,
    oaep: OAEPDecrypt<H, R>,
}

pub struct PKCS1EncryptStream<R: Rand> {
    buf: Vec<u8>,
    pkcs: PKCS1Encrypt<R>,
}

pub struct PKCS1DecryptStream<R: Rand> {
    buf: Vec<u8>,
    pkcs: PKCS1Decrypt<R>,
}

impl<H: DigestX, R: Rand> From<OAEPEncrypt<H, R>> for OAEPEncryptStream<H, R> {
    fn from(value: OAEPEncrypt<H, R>) -> Self {
        Self {
            buf: Vec::with_capacity(1024),
            oaep: value,
        }
    }
}

impl<H: DigestX, R: Rand> From<OAEPDecrypt<H, R>> for OAEPEncryptStream<H, R> {
    fn from(value: OAEPDecrypt<H, R>) -> Self {
        Self {
            buf: Vec::with_capacity(1024),
            oaep: value.into(),
        }
    }
}

impl<H: DigestX, R: Rand> From<OAEPDecrypt<H, R>> for OAEPDecryptStream<H, R> {
    fn from(value: OAEPDecrypt<H, R>) -> Self {
        Self {
            buf: Vec::with_capacity(1024),
            oaep: value,
        }
    }
}

impl<H: DigestX, R: Rand> Deref for OAEPEncryptStream<H, R> {
    type Target = OAEPEncrypt<H, R>;
    fn deref(&self) -> &Self::Target {
        &self.oaep
    }
}

impl<H: DigestX, R: Rand> Deref for OAEPDecryptStream<H, R> {
    type Target = OAEPDecrypt<H, R>;
    fn deref(&self) -> &Self::Target {
        &self.oaep
    }
}

impl<R: Rand> From<PKCS1Encrypt<R>> for PKCS1EncryptStream<R> {
    fn from(value: PKCS1Encrypt<R>) -> Self {
        Self {
            buf: Vec::with_capacity(1024),
            pkcs: value,
        }
    }
}

impl<R: Rand> From<PKCS1Decrypt<R>> for PKCS1EncryptStream<R> {
    fn from(value: PKCS1Decrypt<R>) -> Self {
        Self {
            buf: Vec::with_capacity(1024),
            pkcs: value.into(),
        }
    }
}

impl<R: Rand> From<PKCS1Decrypt<R>> for PKCS1DecryptStream<R> {
    fn from(value: PKCS1Decrypt<R>) -> Self {
        Self {
            buf: Vec::with_capacity(1024),
            pkcs: value,
        }
    }
}

impl<R: Rand> Deref for PKCS1EncryptStream<R> {
    type Target = PKCS1Encrypt<R>;
    fn deref(&self) -> &Self::Target {
        &self.pkcs
    }
}

impl<R: Rand> Deref for PKCS1DecryptStream<R> {
    type Target = PKCS1Decrypt<R>;
    fn deref(&self) -> &Self::Target {
        &self.pkcs
    }
}

impl<H: DigestX, R: Rand> OAEPEncryptStream<H, R> {
    pub fn new(oaep: OAEPEncrypt<H, R>) -> Self {
        Self::from(oaep)
    }
}

impl<H: DigestX, R: Rand> OAEPDecryptStream<H, R> {
    pub fn new(oaep: OAEPDecrypt<H, R>) -> Self {
        Self::from(oaep)
    }
}

impl<R: Rand> PKCS1EncryptStream<R> {
    pub fn new(pkcs: PKCS1Encrypt<R>) -> Self {
        Self::from(pkcs)
    }
}

impl<R: Rand> PKCS1DecryptStream<R> {
    pub fn new(pkcs: PKCS1Decrypt<R>) -> Self {
        Self::from(pkcs)
    }
}

impl<H: DigestX, R: Rand> StreamEncrypt for OAEPEncryptStream<H, R> {
    fn stream_encrypt<'a, IR: Read, OW: Write>(
        &'a mut self,
        in_data: &'a mut IR,
        out_data: &mut OW,
    ) -> Result<StreamCipherFinish<'a, Self, IR, OW>, CipherError> {
        let ilen = in_data.read_to_end(&mut self.buf)?;
        let (mut itr, mut olen) = (self.buf.chunks_exact(self.oaep.max_msg_len()), 0);
        for block in &mut itr {
            olen += self.oaep.encrypt_inner(block, out_data)?;
        }

        let rlen = itr.remainder().len();
        self.buf.rotate_right(rlen);
        self.buf.truncate(rlen);

        let finish = StreamCipherFinish::new(self, (ilen, olen), |oaep, out| {
            if !oaep.buf.is_empty() {
                let olen = oaep.oaep.encrypt_inner(oaep.buf.as_slice(), out)?;
                oaep.buf.clear();
                Ok(olen)
            } else {
                Ok(0)
            }
        });

        Ok(finish)
    }
}

impl<H: DigestX, R: Rand> StreamEncrypt for OAEPDecryptStream<H, R> {
    fn stream_encrypt<'a, IR: Read, OW: Write>(
        &'a mut self,
        in_data: &'a mut IR,
        out_data: &mut OW,
    ) -> Result<StreamCipherFinish<'a, Self, IR, OW>, CipherError> {
        let ilen = in_data.read_to_end(&mut self.buf)?;
        let (mut itr, mut olen) = (self.buf.chunks_exact(self.oaep.max_msg_len()), 0);
        for block in &mut itr {
            let tmp: &OAEPEncrypt<H, R> = self.oaep.as_ref();
            olen += tmp.encrypt_inner(block, out_data)?;
        }

        let rlen = itr.remainder().len();
        self.buf.rotate_right(rlen);
        self.buf.truncate(rlen);

        let finish = StreamCipherFinish::new(self, (ilen, olen), |oaep, out| {
            if !oaep.buf.is_empty() {
                let tmp: &OAEPEncrypt<H, R> = oaep.oaep.as_ref();
                let olen = tmp.encrypt_inner(oaep.buf.as_slice(), out)?;
                oaep.buf.clear();
                Ok(olen)
            } else {
                Ok(0)
            }
        });

        Ok(finish)
    }
}

impl<H: DigestX, R: Rand> StreamDecrypt for OAEPDecryptStream<H, R> {
    fn stream_decrypt<'a, IR: Read, OW: Write>(
        &'a mut self,
        in_data: &'a mut IR,
        out_data: &mut OW,
    ) -> Result<StreamCipherFinish<'a, Self, IR, OW>, CipherError> {
        let ilen = in_data.read_to_end(&mut self.buf)?;
        let (mut itr, mut olen) = (self.buf.chunks_exact(self.oaep.key_len()), 0);
        for block in &mut itr {
            olen += self.oaep.decrypt_inner(block, out_data)?;
        }

        let rlen = itr.remainder().len();
        self.buf.rotate_right(rlen);
        self.buf.truncate(rlen);

        let finish = StreamCipherFinish::new(self, (ilen, olen), |oaep, out| {
            if !oaep.buf.is_empty() {
                let olen = oaep.decrypt_inner(oaep.buf.as_slice(), out)?;
                oaep.buf.clear();
                Ok(olen)
            } else {
                Ok(0)
            }
        });

        Ok(finish)
    }
}

impl<R: Rand> StreamEncrypt for PKCS1EncryptStream<R> {
    fn stream_encrypt<'a, IR: Read, OW: Write>(
        &'a mut self,
        in_data: &'a mut IR,
        out_data: &mut OW,
    ) -> Result<StreamCipherFinish<'a, Self, IR, OW>, CipherError> {
        let ilen = in_data.read_to_end(&mut self.buf)?;
        let (mut itr, mut olen) = (self.buf.chunks_exact(self.pkcs.max_msg_len()), 0);
        for block in &mut itr {
            olen += self.pkcs.encrypt_inner(block, out_data)?;
        }

        let rlen = itr.remainder().len();
        self.buf.rotate_right(rlen);
        self.buf.truncate(rlen);

        let finish = StreamCipherFinish::new(self, (ilen, olen), |pkcs, out| {
            if !pkcs.buf.is_empty() {
                let olen = pkcs.pkcs.encrypt_inner(pkcs.buf.as_slice(), out)?;
                pkcs.buf.clear();
                Ok(olen)
            } else {
                Ok(0)
            }
        });

        Ok(finish)
    }
}

impl<R: Rand> StreamEncrypt for PKCS1DecryptStream<R> {
    fn stream_encrypt<'a, IR: Read, OW: Write>(
        &'a mut self,
        in_data: &'a mut IR,
        out_data: &mut OW,
    ) -> Result<StreamCipherFinish<'a, Self, IR, OW>, CipherError> {
        let ilen = in_data.read_to_end(&mut self.buf)?;
        let (mut itr, mut olen) = (self.buf.chunks_exact(self.pkcs.max_msg_len()), 0);
        for block in &mut itr {
            olen += self.pkcs.as_ref().encrypt_inner(block, out_data)?;
        }

        let rlen = itr.remainder().len();
        self.buf.rotate_right(rlen);
        self.buf.truncate(rlen);

        let finish = StreamCipherFinish::new(self, (ilen, olen), |pkcs, out| {
            if !pkcs.buf.is_empty() {
                let olen = pkcs.pkcs.as_ref().encrypt_inner(pkcs.buf.as_slice(), out)?;
                pkcs.buf.clear();
                Ok(olen)
            } else {
                Ok(0)
            }
        });

        Ok(finish)
    }
}

impl<R: Rand> StreamDecrypt for PKCS1DecryptStream<R> {
    fn stream_decrypt<'a, IR: Read, OW: Write>(
        &'a mut self,
        in_data: &'a mut IR,
        out_data: &mut OW,
    ) -> Result<StreamCipherFinish<'a, Self, IR, OW>, CipherError> {
        let ilen = in_data.read_to_end(&mut self.buf)?;
        let (mut itr, mut olen) = (self.buf.chunks_exact(self.pkcs.key_len()), 0);
        for block in &mut itr {
            olen += self.pkcs.decrypt_inner(block, out_data)?;
        }

        let rlen = itr.remainder().len();
        self.buf.rotate_right(rlen);
        self.buf.truncate(rlen);

        let finish = StreamCipherFinish::new(self, (ilen, olen), |pkcs, out| {
            if !pkcs.buf.is_empty() {
                let olen = pkcs.decrypt_inner(pkcs.buf.as_slice(), out)?;
                pkcs.buf.clear();
                Ok(olen)
            } else {
                Ok(0)
            }
        });

        Ok(finish)
    }
}

#[cfg(test)]
mod tests {
    use crate::rsa::{
        OAEPDecrypt, OAEPDecryptStream, OAEPEncrypt, OAEPEncryptStream, PrivateKey, PublicKey,
    };
    use crate::DefaultRand;
    use crate::{Rand, StreamDecrypt, StreamEncrypt};
    use crypto_hash::sha2::SHA1;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[derive(Default)]
    struct TestRand {
        rd: Vec<u8>,
    }

    impl TestRand {
        fn new(rd: &[u8]) -> Self {
            Self { rd: rd.to_vec() }
        }
    }

    impl Rand for TestRand {
        fn rand(&mut self, random: &mut [u8]) {
            random
                .iter_mut()
                .zip(self.rd.iter())
                .for_each(|(a, &b)| *a = b);
        }
    }

    struct TestEncryptOAEPMessage {
        in_msg: Vec<u8>,
        seed: Vec<u8>,
        out_msg: Vec<u8>,
    }

    struct TestEncryptOAEPData {
        modulus: &'static str,
        e: u32,
        d: &'static str,
        msgs: Vec<TestEncryptOAEPMessage>,
    }

    fn oaep_get_test_datas() -> Vec<TestEncryptOAEPData> {
        // These test datas come from golang source code
        vec![
            TestEncryptOAEPData {
                modulus: "0xa8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
                e: 65537u32,
                d: "0x53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1",
                msgs: vec![
                    TestEncryptOAEPMessage {
                        in_msg: vec![0x66u8, 0x28, 0x19, 0x4e, 0x12, 0x07, 0x3d, 0xb0,
                                     0x3b, 0xa9, 0x4c, 0xda, 0x9e, 0xf9, 0x53, 0x23, 0x97,
                                     0xd5, 0x0d, 0xba, 0x79, 0xb9, 0x87, 0x00, 0x4a, 0xfe,
                                     0xfe, 0x34,
                        ],
                        seed: vec![0x18u8, 0xb7, 0x76, 0xea, 0x21, 0x06, 0x9d, 0x69,
                                   0x77, 0x6a, 0x33, 0xe9, 0x6b, 0xad, 0x48, 0xe1, 0xdd,
                                   0xa0, 0xa5, 0xef,
                        ],
                        out_msg: vec![0x35u8, 0x4f, 0xe6, 0x7b, 0x4a, 0x12, 0x6d, 0x5d,
                                      0x35, 0xfe, 0x36, 0xc7, 0x77, 0x79, 0x1a, 0x3f, 0x7b,
                                      0xa1, 0x3d, 0xef, 0x48, 0x4e, 0x2d, 0x39, 0x08, 0xaf,
                                      0xf7, 0x22, 0xfa, 0xd4, 0x68, 0xfb, 0x21, 0x69, 0x6d,
                                      0xe9, 0x5d, 0x0b, 0xe9, 0x11, 0xc2, 0xd3, 0x17, 0x4f,
                                      0x8a, 0xfc, 0xc2, 0x01, 0x03, 0x5f, 0x7b, 0x6d, 0x8e,
                                      0x69, 0x40, 0x2d, 0xe5, 0x45, 0x16, 0x18, 0xc2, 0x1a,
                                      0x53, 0x5f, 0xa9, 0xd7, 0xbf, 0xc5, 0xb8, 0xdd, 0x9f,
                                      0xc2, 0x43, 0xf8, 0xcf, 0x92, 0x7d, 0xb3, 0x13, 0x22,
                                      0xd6, 0xe8, 0x81, 0xea, 0xa9, 0x1a, 0x99, 0x61, 0x70,
                                      0xe6, 0x57, 0xa0, 0x5a, 0x26, 0x64, 0x26, 0xd9, 0x8c,
                                      0x88, 0x00, 0x3f, 0x84, 0x77, 0xc1, 0x22, 0x70, 0x94,
                                      0xa0, 0xd9, 0xfa, 0x1e, 0x8c, 0x40, 0x24, 0x30, 0x9c,
                                      0xe1, 0xec, 0xcc, 0xb5, 0x21, 0x00, 0x35, 0xd4, 0x7a,
                                      0xc7, 0x2e, 0x8a,
                        ],
                    },

                    TestEncryptOAEPMessage {
                        in_msg: vec![0x75, 0x0c, 0x40, 0x47, 0xf5, 0x47, 0xe8, 0xe4,
                                     0x14, 0x11, 0x85, 0x65, 0x23, 0x29, 0x8a, 0xc9, 0xba,
                                     0xe2, 0x45, 0xef, 0xaf, 0x13, 0x97, 0xfb, 0xe5, 0x6f,
                                     0x9d, 0xd5,
                        ],
                        seed: vec![0x0c, 0xc7, 0x42, 0xce, 0x4a, 0x9b, 0x7f, 0x32,
                                   0xf9, 0x51, 0xbc, 0xb2, 0x51, 0xef, 0xd9, 0x25, 0xfe,
                                   0x4f, 0xe3, 0x5f,
                        ],
                        out_msg: vec![0x64, 0x0d, 0xb1, 0xac, 0xc5, 0x8e, 0x05, 0x68,
                                      0xfe, 0x54, 0x07, 0xe5, 0xf9, 0xb7, 0x01, 0xdf, 0xf8,
                                      0xc3, 0xc9, 0x1e, 0x71, 0x6c, 0x53, 0x6f, 0xc7, 0xfc,
                                      0xec, 0x6c, 0xb5, 0xb7, 0x1c, 0x11, 0x65, 0x98, 0x8d,
                                      0x4a, 0x27, 0x9e, 0x15, 0x77, 0xd7, 0x30, 0xfc, 0x7a,
                                      0x29, 0x93, 0x2e, 0x3f, 0x00, 0xc8, 0x15, 0x15, 0x23,
                                      0x6d, 0x8d, 0x8e, 0x31, 0x01, 0x7a, 0x7a, 0x09, 0xdf,
                                      0x43, 0x52, 0xd9, 0x04, 0xcd, 0xeb, 0x79, 0xaa, 0x58,
                                      0x3a, 0xdc, 0xc3, 0x1e, 0xa6, 0x98, 0xa4, 0xc0, 0x52,
                                      0x83, 0xda, 0xba, 0x90, 0x89, 0xbe, 0x54, 0x91, 0xf6,
                                      0x7c, 0x1a, 0x4e, 0xe4, 0x8d, 0xc7, 0x4b, 0xbb, 0xe6,
                                      0x64, 0x3a, 0xef, 0x84, 0x66, 0x79, 0xb4, 0xcb, 0x39,
                                      0x5a, 0x35, 0x2d, 0x5e, 0xd1, 0x15, 0x91, 0x2d, 0xf6,
                                      0x96, 0xff, 0xe0, 0x70, 0x29, 0x32, 0x94, 0x6d, 0x71,
                                      0x49, 0x2b, 0x44,
                        ],
                    },

                    TestEncryptOAEPMessage {
                        in_msg: vec![0xd9, 0x4a, 0xe0, 0x83, 0x2e, 0x64, 0x45, 0xce,
                                     0x42, 0x33, 0x1c, 0xb0, 0x6d, 0x53, 0x1a, 0x82, 0xb1,
                                     0xdb, 0x4b, 0xaa, 0xd3, 0x0f, 0x74, 0x6d, 0xc9, 0x16,
                                     0xdf, 0x24, 0xd4, 0xe3, 0xc2, 0x45, 0x1f, 0xff, 0x59,
                                     0xa6, 0x42, 0x3e, 0xb0, 0xe1, 0xd0, 0x2d, 0x4f, 0xe6,
                                     0x46, 0xcf, 0x69, 0x9d, 0xfd, 0x81, 0x8c, 0x6e, 0x97,
                                     0xb0, 0x51,
                        ],
                        seed: vec![0x25, 0x14, 0xdf, 0x46, 0x95, 0x75, 0x5a, 0x67,
                                   0xb2, 0x88, 0xea, 0xf4, 0x90, 0x5c, 0x36, 0xee, 0xc6,
                                   0x6f, 0xd2, 0xfd,
                        ],
                        out_msg: vec![0x42, 0x37, 0x36, 0xed, 0x03, 0x5f, 0x60, 0x26,
                                      0xaf, 0x27, 0x6c, 0x35, 0xc0, 0xb3, 0x74, 0x1b, 0x36,
                                      0x5e, 0x5f, 0x76, 0xca, 0x09, 0x1b, 0x4e, 0x8c, 0x29,
                                      0xe2, 0xf0, 0xbe, 0xfe, 0xe6, 0x03, 0x59, 0x5a, 0xa8,
                                      0x32, 0x2d, 0x60, 0x2d, 0x2e, 0x62, 0x5e, 0x95, 0xeb,
                                      0x81, 0xb2, 0xf1, 0xc9, 0x72, 0x4e, 0x82, 0x2e, 0xca,
                                      0x76, 0xdb, 0x86, 0x18, 0xcf, 0x09, 0xc5, 0x34, 0x35,
                                      0x03, 0xa4, 0x36, 0x08, 0x35, 0xb5, 0x90, 0x3b, 0xc6,
                                      0x37, 0xe3, 0x87, 0x9f, 0xb0, 0x5e, 0x0e, 0xf3, 0x26,
                                      0x85, 0xd5, 0xae, 0xc5, 0x06, 0x7c, 0xd7, 0xcc, 0x96,
                                      0xfe, 0x4b, 0x26, 0x70, 0xb6, 0xea, 0xc3, 0x06, 0x6b,
                                      0x1f, 0xcf, 0x56, 0x86, 0xb6, 0x85, 0x89, 0xaa, 0xfb,
                                      0x7d, 0x62, 0x9b, 0x02, 0xd8, 0xf8, 0x62, 0x5c, 0xa3,
                                      0x83, 0x36, 0x24, 0xd4, 0x80, 0x0f, 0xb0, 0x81, 0xb1,
                                      0xcf, 0x94, 0xeb,
                        ],
                    }
                ],
            },

            TestEncryptOAEPData {
                modulus: "0xae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2fa1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a03381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aefa2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb",
                e: 65537u32,
                d: "0x056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e596a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbebe57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f102cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c430ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79",
                msgs: vec![
                    TestEncryptOAEPMessage {
                        in_msg: vec![0x8b, 0xba, 0x6b, 0xf8, 0x2a, 0x6c, 0x0f, 0x86,
                                     0xd5, 0xf1, 0x75, 0x6e, 0x97, 0x95, 0x68, 0x70, 0xb0,
                                     0x89, 0x53, 0xb0, 0x6b, 0x4e, 0xb2, 0x05, 0xbc, 0x16,
                                     0x94, 0xee,
                        ],
                        seed: vec![0x47, 0xe1, 0xab, 0x71, 0x19, 0xfe, 0xe5, 0x6c,
                                   0x95, 0xee, 0x5e, 0xaa, 0xd8, 0x6f, 0x40, 0xd0, 0xaa,
                                   0x63, 0xbd, 0x33,
                        ],
                        out_msg: vec![0x53, 0xea, 0x5d, 0xc0, 0x8c, 0xd2, 0x60, 0xfb,
                                      0x3b, 0x85, 0x85, 0x67, 0x28, 0x7f, 0xa9, 0x15, 0x52,
                                      0xc3, 0x0b, 0x2f, 0xeb, 0xfb, 0xa2, 0x13, 0xf0, 0xae,
                                      0x87, 0x70, 0x2d, 0x06, 0x8d, 0x19, 0xba, 0xb0, 0x7f,
                                      0xe5, 0x74, 0x52, 0x3d, 0xfb, 0x42, 0x13, 0x9d, 0x68,
                                      0xc3, 0xc5, 0xaf, 0xee, 0xe0, 0xbf, 0xe4, 0xcb, 0x79,
                                      0x69, 0xcb, 0xf3, 0x82, 0xb8, 0x04, 0xd6, 0xe6, 0x13,
                                      0x96, 0x14, 0x4e, 0x2d, 0x0e, 0x60, 0x74, 0x1f, 0x89,
                                      0x93, 0xc3, 0x01, 0x4b, 0x58, 0xb9, 0xb1, 0x95, 0x7a,
                                      0x8b, 0xab, 0xcd, 0x23, 0xaf, 0x85, 0x4f, 0x4c, 0x35,
                                      0x6f, 0xb1, 0x66, 0x2a, 0xa7, 0x2b, 0xfc, 0xc7, 0xe5,
                                      0x86, 0x55, 0x9d, 0xc4, 0x28, 0x0d, 0x16, 0x0c, 0x12,
                                      0x67, 0x85, 0xa7, 0x23, 0xeb, 0xee, 0xbe, 0xff, 0x71,
                                      0xf1, 0x15, 0x94, 0x44, 0x0a, 0xae, 0xf8, 0x7d, 0x10,
                                      0x79, 0x3a, 0x87, 0x74, 0xa2, 0x39, 0xd4, 0xa0, 0x4c,
                                      0x87, 0xfe, 0x14, 0x67, 0xb9, 0xda, 0xf8, 0x52, 0x08,
                                      0xec, 0x6c, 0x72, 0x55, 0x79, 0x4a, 0x96, 0xcc, 0x29,
                                      0x14, 0x2f, 0x9a, 0x8b, 0xd4, 0x18, 0xe3, 0xc1, 0xfd,
                                      0x67, 0x34, 0x4b, 0x0c, 0xd0, 0x82, 0x9d, 0xf3, 0xb2,
                                      0xbe, 0xc6, 0x02, 0x53, 0x19, 0x62, 0x93, 0xc6, 0xb3,
                                      0x4d, 0x3f, 0x75, 0xd3, 0x2f, 0x21, 0x3d, 0xd4, 0x5c,
                                      0x62, 0x73, 0xd5, 0x05, 0xad, 0xf4, 0xcc, 0xed, 0x10,
                                      0x57, 0xcb, 0x75, 0x8f, 0xc2, 0x6a, 0xee, 0xfa, 0x44,
                                      0x12, 0x55, 0xed, 0x4e, 0x64, 0xc1, 0x99, 0xee, 0x07,
                                      0x5e, 0x7f, 0x16, 0x64, 0x61, 0x82, 0xfd, 0xb4, 0x64,
                                      0x73, 0x9b, 0x68, 0xab, 0x5d, 0xaf, 0xf0, 0xe6, 0x3e,
                                      0x95, 0x52, 0x01, 0x68, 0x24, 0xf0, 0x54, 0xbf, 0x4d,
                                      0x3c, 0x8c, 0x90, 0xa9, 0x7b, 0xb6, 0xb6, 0x55, 0x32,
                                      0x84, 0xeb, 0x42, 0x9f, 0xcc,
                        ],
                    }
                ],
            }
        ]
    }

    #[test]
    fn oaep_encrypt() {
        let cases = oaep_get_test_datas();

        let mut cipher = vec![];
        for (i, ele) in cases.iter().enumerate() {
            let (n, e) = (
                BigUint::from_str_radix(&ele.modulus[2..], 16).unwrap(),
                BigUint::from(ele.e),
            );
            let pk = PublicKey::new_uncheck(n, e);

            for (j, msg) in ele.msgs.iter().enumerate() {
                cipher.clear();
                let (sha1, rd) = (SHA1::new(), TestRand::new(msg.seed.as_slice()));

                let oaep = OAEPEncrypt::new(pk.clone(), sha1, rd, &[]).unwrap();
                let mut stream = OAEPEncryptStream::new(oaep);
                let tmp = &mut msg.in_msg.as_slice();
                let finish = stream.stream_encrypt(tmp, &mut cipher).unwrap();
                let len = finish.finish(&mut cipher).unwrap();

                assert_eq!(
                    len.0,
                    msg.in_msg.len(),
                    "case: {}-{}, read data length not match",
                    i,
                    j
                );
                assert_eq!(
                    len.1,
                    msg.out_msg.len(),
                    "case: {}-{}, write data length not match",
                    i,
                    j
                );
                assert_eq!(
                    cipher.as_slice(),
                    msg.out_msg.as_slice(),
                    "case: {}-{}",
                    i,
                    j
                );
            }
        }
    }

    #[test]
    fn oaep_decrypt() {
        let cases = oaep_get_test_datas();

        let mut plaintxt = vec![];
        for (i, ele) in cases.iter().enumerate() {
            let (n, e, d) = (
                BigUint::from_str_radix(&ele.modulus[2..], 16).unwrap(),
                BigUint::from(ele.e),
                BigUint::from_str_radix(&ele.d[2..], 16).unwrap(),
            );
            let key = PrivateKey::new_uncheck(n, e, d);

            for (j, msg) in ele.msgs.iter().enumerate() {
                let (sha1, rd) = (SHA1::new(), TestRand::new(msg.seed.as_slice()));

                plaintxt.clear();
                let oaep = OAEPDecrypt::new_uncheck(key.clone(), sha1, rd, &[]).unwrap();
                let mut stream = OAEPDecryptStream::new(oaep);
                let tmp = &mut msg.out_msg.as_slice();
                let finish = stream.stream_decrypt(tmp, &mut plaintxt).unwrap();
                let len = finish.finish(&mut plaintxt).unwrap();
                assert_eq!(
                    len.0,
                    msg.out_msg.len(),
                    "case: {}-{}, read data length not match",
                    i,
                    j
                );
                assert_eq!(
                    len.1,
                    msg.in_msg.len(),
                    "case: {}-{}, write data length not match",
                    i,
                    j
                );
                assert_eq!(
                    plaintxt.as_slice(),
                    msg.in_msg.as_slice(),
                    "case: {}-{}",
                    i,
                    j
                );

                plaintxt.clear();
                let (sha1, rd) = (SHA1::new(), DefaultRand::default());
                let oaep = OAEPDecrypt::new_uncheck(key.clone(), sha1, rd, &[]).unwrap();
                let mut stream = OAEPDecryptStream::new(oaep);
                let tmp = &mut msg.out_msg.as_slice();
                let finish = stream.stream_decrypt(tmp, &mut plaintxt).unwrap();
                let len = finish.finish(&mut plaintxt).unwrap();
                assert_eq!(
                    len.0,
                    msg.out_msg.len(),
                    "case: {}-{}, read data length not match",
                    i,
                    j
                );
                assert_eq!(
                    len.1,
                    msg.in_msg.len(),
                    "case: {}-{}, write data length not match",
                    i,
                    j
                );
                assert_eq!(
                    plaintxt.as_slice(),
                    msg.in_msg.as_slice(),
                    "case: {}-{}",
                    i,
                    j
                );
            }
        }
    }
}
