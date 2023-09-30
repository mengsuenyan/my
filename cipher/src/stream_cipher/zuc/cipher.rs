use crate::stream_cipher::zuc::ZUCKey;
use crate::{CipherError, StreamCipherFinish, StreamDecrypt, StreamEncrypt};
use std::io::{Read, Write};

/// 流加密
///
/// [ZUC](http://www.gmbz.org.cn/main/viewfile/20180107233806310781.html)
#[derive(Clone)]
pub struct ZUC {
    key: ZUCKey,
    key_src: ZUCKey,
    buf: Vec<u8>,
    ilen: usize,
    is_encrypt: Option<bool>,
}

impl ZUC {
    /// `count, bearer, direction`参与初始化向量`IV`的生成. <br>
    /// `bearer`: 只有最低有效位的5位有效;
    ///
    /// ```txt
    /// iv[0..4] = count.to_be_bytes()
    /// iv[4] = bearer & 0x1f || direction as u8 || 00
    /// iv[5] = iv[6] = iv[7] = 0
    /// iv[j+8] = iv[j], 0 <= j <= 7
    /// ```
    pub fn new(count: u32, bearer: u8, direction: bool, key: [u8; ZUCKey::KEY_SIZE]) -> Self {
        let mut iv = [0u8; ZUCKey::KEY_SIZE];
        iv.iter_mut()
            .zip(count.to_be_bytes())
            .for_each(|(a, b)| *a = b);
        iv[4] = (bearer & 0x1f) << 3 | (direction as u8) << 2;
        (0..=7).for_each(|i| iv[i + 8] = iv[i]);

        let zuc_key = ZUCKey::new(key, iv);

        Self {
            key: zuc_key.clone(),
            key_src: zuc_key,
            buf: Vec::with_capacity(4),
            ilen: 0,
            is_encrypt: None,
        }
    }

    fn set_working_flag(&mut self, is_encrypt: bool) -> Result<(), CipherError> {
        match self.is_encrypt {
            None => {
                self.is_encrypt = Some(is_encrypt);
                Ok(())
            }
            Some(b) => {
                if b != is_encrypt {
                    Err(CipherError::BeWorking(b))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn reset(&mut self) {
        self.key_src = self.key.clone();
        self.is_encrypt = None;
        self.buf.clear();
        self.ilen = 0;
    }

    fn cipher_inner<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), CipherError> {
        let mut buf = [0u8; 2048];
        let mut olen = 0;

        loop {
            let l = in_data.read(&mut buf)?;
            let mut buf = &buf[..l];
            self.ilen += l;
            if self.ilen >= (u32::MAX as usize >> 5) {
                return Err(CipherError::Other(format!(
                    "ZUC cipher data exceed {}",
                    u32::MAX >> 5
                )));
            }
            if l == 0 {
                break;
            }

            if !self.buf.is_empty() {
                let tmp = self.buf.len().min(l);
                self.buf
                    .iter_mut()
                    .zip(buf.iter().take(tmp))
                    .for_each(|(a, &b)| *a ^= b);
                out_data.write_all(&self.buf[..tmp])?;
                let buf_len = self.buf.len();
                self.buf.rotate_right(buf_len - tmp);
                self.buf.truncate(buf_len - tmp);
                olen += tmp;
                buf = &buf[tmp..];
            }

            let mut itr = buf.chunks_exact(4);
            for d in &mut itr {
                let mut k = self.key_src.generate_key().to_be_bytes();
                k[0] ^= d[0];
                k[1] ^= d[1];
                k[2] ^= d[2];
                k[3] ^= d[3];
                out_data.write_all(&k)?;
                olen += 4;
            }

            if !itr.remainder().is_empty() {
                let mut k = self.key_src.generate_key().to_be_bytes();
                k.iter_mut()
                    .zip(itr.remainder())
                    .for_each(|(a, &b)| *a ^= b);
                out_data.write_all(&k[..itr.remainder().len()])?;
                olen += itr.remainder().len();
                self.buf.extend(&k[itr.remainder().len()..]);
            }
        }

        Ok((self.ilen, olen))
    }
}

impl StreamEncrypt for ZUC {
    fn stream_encrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(true)?;

        let (ilen, olen) = self.cipher_inner(in_data, out_data)?;
        let s = StreamCipherFinish::new(self, (ilen, olen), |sf, _outdata: &mut W| {
            sf.reset();
            Ok(0)
        });

        Ok(s)
    }
}

impl StreamDecrypt for ZUC {
    fn stream_decrypt<'a, R: Read, W: Write>(
        &'a mut self,
        in_data: &'a mut R,
        out_data: &mut W,
    ) -> Result<StreamCipherFinish<'a, Self, R, W>, CipherError> {
        self.set_working_flag(false)?;

        let (ilen, olen) = self.cipher_inner(in_data, out_data)?;
        let s = StreamCipherFinish::new(self, (ilen, olen), |sf, _outdata: &mut W| {
            sf.reset();
            Ok(0)
        });

        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use crate::stream_cipher::zuc::ZUC;
    use crate::{StreamDecrypt, StreamEncrypt};

    struct Cases {
        ck: [u8; 16],
        count: u32,
        bearer: u8,
        direction: u8,
        bits_len: u32,
        ibs: Vec<u32>,
        obs: Vec<u32>,
    }

    #[test]
    fn zuc() {
        let cases = [
            Cases {
                ck: [
                    0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70,
                    0xf0, 0x0a, 0x29,
                ],
                count: 0x66035492,
                bearer: 0xf,
                direction: 0,
                bits_len: 0xc1,
                ibs: vec![
                    0x6cf65340, 0x735552ab, 0x0c9752fa, 0x6f9025fe, 0x0bd675d9, 0x005875b2,
                    0x00000000,
                ],
                obs: vec![
                    0xa6c85fc6, 0x6afb8533, 0xaafc2518, 0xdfe78494, 0x0ee1e4b0, 0x30238cc8,
                    0x00000000,
                ],
            },
            Cases {
                ck: [
                    0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd,
                    0x54, 0x30, 0x2a,
                ],
                count: 0x56823,
                bearer: 0x18,
                direction: 1,
                bits_len: 0x320,
                ibs: vec![
                    0x14a8ef69, 0x3d678507, 0xbbe7270a, 0x7f67ff50, 0x06c3525b, 0x9807e467,
                    0xc4e56000, 0xba338f5d, 0x42955903, 0x67518222, 0x46c80d3b, 0x38f07f4b,
                    0xe2d8ff58, 0x05f51322, 0x29bde93b, 0xbbdcaf38, 0x2bf1ee97, 0x2fbf9977,
                    0xbada8945, 0x847a2a6c, 0x9ad34a66, 0x7554e04d, 0x1f7fa2c3, 0x3241bd8f,
                    0x01ba220d,
                ],
                obs: vec![
                    0x131d43e0, 0xdea1be5c, 0x5a1bfd97, 0x1d852cbf, 0x712d7b4f, 0x57961fea,
                    0x3208afa8, 0xbca433f4, 0x56ad09c7, 0x417e58bc, 0x69cf8866, 0xd1353f74,
                    0x865e8078, 0x1d202dfb, 0x3ecff7fc, 0xbc3b190f, 0xe82a204e, 0xd0e350fc,
                    0x0f6f2613, 0xb2f2bca6, 0xdf5a473a, 0x57a4a00d, 0x985ebad8, 0x80d6f238,
                    0x64a07b01,
                ],
            },
            Cases {
                ck: [
                    0xe1, 0x3f, 0xed, 0x21, 0xb4, 0x6e, 0x4e, 0x7e, 0xc3, 0x12, 0x53, 0xb2, 0xbb,
                    0x17, 0xb3, 0xe0,
                ],
                count: 0x2738cdaa,
                bearer: 0x1a,
                direction: 0,
                bits_len: 0xfb3,
                ibs: vec![
                    0x8d74e20d, 0x54894e06, 0xd3cb13cb, 0x3933065e, 0x8674be62, 0xadb1c72b,
                    0x3a646965, 0xab63cb7b, 0x7854dfdc, 0x27e84929, 0xf49c64b8, 0x72a490b1,
                    0x3f957b64, 0x827e71f4, 0x1fbd4269, 0xa42c97f8, 0x24537027, 0xf86e9f4a,
                    0xd82d1df4, 0x51690fdd, 0x98b6d03f, 0x3a0ebe3a, 0x312d6b84, 0x0ba5a182,
                    0x0b2a2c97, 0x09c090d2, 0x45ed267c, 0xf845ae41, 0xfa975d33, 0x33ac3009,
                    0xfd40eba9, 0xeb5b8857, 0x14b768b6, 0x97138baf, 0x21380eca, 0x49f644d4,
                    0x8689e421, 0x5760b906, 0x739f0d2b, 0x3f091133, 0xca15d981, 0xcbe401ba,
                    0xf72d05ac, 0xe05cccb2, 0xd297f4ef, 0x6a5f58d9, 0x1246cfa7, 0x7215b892,
                    0xab441d52, 0x78452795, 0xccb7f5d7, 0x9057a1c4, 0xf77f80d4, 0x6db2033c,
                    0xb79bedf8, 0xe60551ce, 0x10c667f6, 0x2a97abaf, 0xabbcd677, 0x2018df96,
                    0xa282ea73, 0x7ce2cb33, 0x1211f60d, 0x5354ce78, 0xf9918d9c, 0x206ca042,
                    0xc9b62387, 0xdd709604, 0xa50af16d, 0x8d35a890, 0x6be484cf, 0x2e74a928,
                    0x99403643, 0x53249b27, 0xb4c9ae29, 0xeddfc7da, 0x6418791a, 0x4e7baa06,
                    0x60fa6451, 0x1f2d685c, 0xc3a5ff70, 0xe0d2b742, 0x92e3b8a0, 0xcd6b04b1,
                    0xc790b8ea, 0xd2703708, 0x540dea2f, 0xc09c3da7, 0x70f65449, 0xc84d817a,
                    0x4f551055, 0xe19ab850, 0x18a0028b, 0x71a144d9, 0x6791e9a3, 0x57793350,
                    0x4eee0060, 0x340c69d2, 0x74e1bf9d, 0x805dcbcc, 0x1a6faa97, 0x6800b6ff,
                    0x2b671dc4, 0x63652fa8, 0xa33ee509, 0x74c1c21b, 0xe01eabb2, 0x16743026,
                    0x9d72ee51, 0x1c9dde30, 0x797c9a25, 0xd86ce74f, 0x5b961be5, 0xfdfb6807,
                    0x814039e7, 0x137636bd, 0x1d7fa9e0, 0x9efd2007, 0x505906a5, 0xac45dfde,
                    0xed7757bb, 0xee745749, 0xc2963335, 0x0bee0ea6, 0xf409df45, 0x80160000,
                ],
                obs: vec![
                    0x94eaa4aa, 0x30a57137, 0xddf09b97, 0xb25618a2, 0x0a13e2f1, 0x0fa5bf81,
                    0x61a879cc, 0x2ae797a6, 0xb4cf2d9d, 0xf31debb9, 0x905ccfec, 0x97de605d,
                    0x21c61ab8, 0x531b7f3c, 0x9da5f039, 0x31f8a064, 0x2de48211, 0xf5f52ffe,
                    0xa10f392a, 0x04766998, 0x5da454a2, 0x8f080961, 0xa6c2b62d, 0xaa17f33c,
                    0xd60a4971, 0xf48d2d90, 0x9394a55f, 0x48117ace, 0x43d708e6, 0xb77d3dc4,
                    0x6d8bc017, 0xd4d1abb7, 0x7b7428c0, 0x42b06f2f, 0x99d8d07c, 0x9879d996,
                    0x00127a31, 0x985f1099, 0xbbd7d6c1, 0x519ede8f, 0x5eeb4a61, 0x0b349ac0,
                    0x1ea23506, 0x91756bd1, 0x05c974a5, 0x3eddb35d, 0x1d4100b0, 0x12e522ab,
                    0x41f4c5f2, 0xfde76b59, 0xcb8b96d8, 0x85cfe408, 0x0d1328a0, 0xd636cc0e,
                    0xdc05800b, 0x76acca8f, 0xef672084, 0xd1f52a8b, 0xbd8e0993, 0x320992c7,
                    0xffbae17c, 0x408441e0, 0xee883fc8, 0xa8b05e22, 0xf5ff7f8d, 0x1b48c74c,
                    0x468c467a, 0x028f09fd, 0x7ce91109, 0xa570a2d5, 0xc4d5f4fa, 0x18c5dd3e,
                    0x4562afe2, 0x4ef77190, 0x1f59af64, 0x5898acef, 0x088abae0, 0x7e92d52e,
                    0xb2de5504, 0x5bb1b7c4, 0x164ef2d7, 0xa6cac15e, 0xeb926d7e, 0xa2f08b66,
                    0xe1f759f3, 0xaee44614, 0x725aa3c7, 0x482b3084, 0x4c143ff8, 0x7b53f1e5,
                    0x83c50125, 0x7dddd096, 0xb81268da, 0xa303f172, 0x34c23335, 0x41f0bb8e,
                    0x190648c5, 0x807c866d, 0x71932286, 0x09adb948, 0x686f7de2, 0x94a802cc,
                    0x38f7fe52, 0x08f5ea31, 0x96d0167b, 0x9bdd02f0, 0xd2a5221c, 0xa508f893,
                    0xaf5c4b4b, 0xb9f4f520, 0xfd84289b, 0x3dbe7e61, 0x497a7e2a, 0x584037ea,
                    0x637b6981, 0x127174af, 0x57b471df, 0x4b2768fd, 0x79c1540f, 0xb3edf2ea,
                    0x22cb69be, 0xc0cf8d93, 0x3d9c6fdd, 0x645e8505, 0x91cca3d6, 0x2c0cc000,
                ],
            },
        ];

        for (i, case) in cases.into_iter().enumerate() {
            let mut zuc = ZUC::new(case.count, case.bearer, case.direction == 1, case.ck);

            let obs = case
                .obs
                .into_iter()
                .map(|x| x.to_be_bytes())
                .flatten()
                .take(case.bits_len as usize / 8)
                .collect::<Vec<_>>();
            let ibs = case
                .ibs
                .into_iter()
                .map(|x| x.to_be_bytes())
                .flatten()
                .take(case.bits_len as usize / 8)
                .collect::<Vec<_>>();

            let mut buf = vec![];
            let (ilen, olen) = zuc
                .stream_encrypt(&mut ibs.as_slice(), &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();

            assert_eq!(ilen, olen, "case {i} stream encrypt failed");
            assert_eq!(obs, buf, "case {i} stream encrypt failed");

            buf.clear();
            let (ilen, olen) = zuc
                .stream_decrypt(&mut obs.as_slice(), &mut buf)
                .unwrap()
                .finish(&mut buf)
                .unwrap();

            assert_eq!(ilen, olen, "case {i} stream decrypt failed");
            assert_eq!(ibs, buf, "case {i} stream decrypt failed");
        }
    }
}
