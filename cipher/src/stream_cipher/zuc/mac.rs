use crate::stream_cipher::zuc::ZUCKey;
use crate::MAC;
use std::io::{Error, ErrorKind, Write};

/// 消息认证码
///
/// [ZUCMac](http://www.gmbz.org.cn/main/viewfile/20180107234058336917.html)
///
/// 注: 规范输出的MAC是32位(`N=4`), 位长度太短并不安全, 这里给出变体实现可以指定输出字节长度。
pub struct ZUCMac<const N: usize> {
    key: ZUCKey,
    key_src: ZUCKey,
    digest: Vec<u32>,
    key_buf: Vec<u32>,
    ilen: usize,
    is_finalize: bool,
}

impl<const N: usize> ZUCMac<N> {
    /// `count, bearer, direction`参与初始化向量`IV`的生成. <br>
    /// `bearer`: 只有最低有效位的5位有效;
    pub fn new(count: u32, bearer: u8, direction: bool, key: [u8; ZUCKey::KEY_SIZE]) -> Self {
        let mut iv = [0u8; ZUCKey::KEY_SIZE];
        iv.iter_mut()
            .zip(count.to_be_bytes())
            .for_each(|(a, b)| *a = b);
        iv[4] = (bearer & 0x1f) << 3;
        iv[8] = iv[0] ^ ((direction as u8) << 7);
        iv[9] = iv[1];
        (2..=5).for_each(|j| iv[j + 8] = iv[j]);
        iv[14] = iv[6] ^ ((direction as u8) << 7);
        iv[15] = iv[7];

        let key = ZUCKey::new(key, iv);

        let mut key_src = key.clone();
        let (mut digest, mut key_buf) = (vec![], vec![]);
        digest.resize((N + 3) >> 2, 0);
        for _ in 0..=digest.len() {
            key_buf.push(key_src.generate_key());
        }

        Self {
            key_src,
            key,
            digest,
            key_buf,
            ilen: 0,
            is_finalize: false,
        }
    }

    fn shift_left(&mut self, sl: usize) {
        if sl != 0 {
            self.key_buf[0] <<= sl;

            let mask = (1 << sl) - 1;
            for i in 1..self.key_buf.len() {
                self.key_buf[i - 1] |= (self.key_buf[i] >> (32 - sl)) & mask;
                self.key_buf[i] <<= sl;
            }
        }

        let rem = self.ilen & 31;
        if rem == 0 {
            let _x = self.key_buf.pop();
            self.key_buf.push(self.key_src.generate_key());
        }
    }
}

impl<const N: usize> Write for ZUCMac<N> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if N == 0 {
            return Ok(0);
        } else if self.is_finalize {
            self.reset();
        }

        let data_len = data.len();
        if self.ilen + data_len >= ((u32::MAX as usize >> 3) / N - 2) {
            return Err(Error::new(
                ErrorKind::Other,
                format!("ZUCMac data length exceed {}", (u32::MAX >> 5) - 1),
            ));
        }

        for &d in data.iter() {
            for i in (0usize..8).rev() {
                if d & (1 << i) != 0 {
                    for (x, &y) in self.digest.iter_mut().zip(self.key_buf.iter()) {
                        *x ^= y;
                    }
                }

                self.ilen += 1;
                self.shift_left(1);
            }
        }

        Ok(data_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<const N: usize> MAC for ZUCMac<N> {
    /// 消息流不足`N`字节, 补0对齐;
    const BLOCK_SIZE: usize = 1;
    const DIGEST_SIZE: usize = N;

    fn mac(&mut self) -> Vec<u8> {
        if self.is_finalize {
            return self
                .digest
                .iter()
                .flat_map(|x| x.to_be_bytes())
                .take(N)
                .collect();
        }

        for (x, &y) in self.digest.iter_mut().zip(self.key_buf.iter()) {
            *x ^= y;
        }
        let l = self.digest.len();
        while self.key_buf.len() < (l << 1) {
            self.key_buf.push(self.key_src.generate_key());
        }
        for (x, &y) in self.digest.iter_mut().zip(self.key_buf.iter().skip(l)) {
            *x ^= y;
        }

        self.is_finalize = true;
        self.digest
            .iter()
            .flat_map(|x| x.to_be_bytes())
            .take(N)
            .collect()
    }

    fn reset(&mut self) {
        self.is_finalize = false;
        self.key_src = self.key.clone();

        self.key_buf.clear();
        for _ in 0..=self.digest.len() {
            self.key_buf.push(self.key_src.generate_key());
        }
        self.ilen = 0;
        self.digest.clear();
        self.digest.resize((N + 3) >> 2, 0);
    }
}

#[cfg(test)]
mod tests {
    use crate::stream_cipher::zuc::mac::ZUCMac;
    use crate::MAC;
    use std::io::Write;

    struct Cases {
        ik: [u8; 16],
        count: u32,
        bearer: u8,
        direction: u8,
        // bits_len: u32,
        msg: Vec<u32>,
        mac: u32,
    }

    #[test]
    fn zuc_mac() {
        let cases = [
            Cases {
                ik: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                count: 0,
                bearer: 0,
                direction: 0,
                // bits_len: 1,
                msg: vec![0],
                // mac: 0xc8a9595e,
                mac: 0x8654676c,
            },
            Cases {
                ik: [
                    0xc9, 0xe6, 0xce, 0xc4, 0x60, 0x7c, 0x72, 0xdb, 0x00, 0x0a, 0xef, 0xa8, 0x83,
                    0x85, 0xab, 0x0a,
                ],
                count: 0xa94059da,
                bearer: 0xa,
                direction: 1,
                // bits_len: 0x241,
                msg: vec![
                    0x983b41d4, 0x7d780c9e, 0x1ad11d7e, 0xb70391b1, 0xde0b35da, 0x2dc62f83,
                    0xe7b78d63, 0x06ca0ea0, 0x7e941b7b, 0xe91348f9, 0xfcb170e2, 0x217fecd9,
                    0x7f9f68ad, 0xb16e5d7d, 0x21e569d2, 0x80ed775c, 0xebde3f40, 0x93c53881,
                    0x00000000,
                ],
                // mac: 0xfae8ff0b,
                mac: 0x99d8a41f,
            },
            Cases {
                ik: [
                    0x6b, 0x8b, 0x08, 0xee, 0x79, 0xe0, 0xb5, 0x98, 0x2d, 0x6d, 0x12, 0x8e, 0xa9,
                    0xf2, 0x20, 0xcb,
                ],
                count: 0x561eb2dd,
                bearer: 0x1c,
                direction: 0,
                // bits_len: 0x1626,
                msg: vec![
                    0x5bad7247, 0x10ba1c56, 0xd5a315f8, 0xd40f6e09, 0x3780be8e, 0x8de07b69,
                    0x92432018, 0xe08ed96a, 0x5734af8b, 0xad8a575d, 0x3a1f162f, 0x85045cc7,
                    0x70925571, 0xd9f5b94e, 0x454a77c1, 0x6e72936b, 0xf016ae15, 0x7499f054,
                    0x3b5d52ca, 0xa6dbeab6, 0x97d2bb73, 0xe41b8075, 0xdce79b4b, 0x86044f66,
                    0x1d4485a5, 0x43dd7860, 0x6e0419e8, 0x059859d3, 0xcb2b67ce, 0x0977603f,
                    0x81ff839e, 0x33185954, 0x4cfbc8d0, 0x0fef1a4c, 0x8510fb54, 0x7d6b06c6,
                    0x11ef44f1, 0xbce107cf, 0xa45a06aa, 0xb360152b, 0x28dc1ebe, 0x6f7fe09b,
                    0x0516f9a5, 0xb02a1bd8, 0x4bb0181e, 0x2e89e19b, 0xd8125930, 0xd178682f,
                    0x3862dc51, 0xb636f04e, 0x720c47c3, 0xce51ad70, 0xd94b9b22, 0x55fbae90,
                    0x6549f499, 0xf8c6d399, 0x47ed5e5d, 0xf8e2def1, 0x13253e7b, 0x08d0a76b,
                    0x6bfc68c8, 0x12f375c7, 0x9b8fe5fd, 0x85976aa6, 0xd46b4a23, 0x39d8ae51,
                    0x47f680fb, 0xe70f978b, 0x38effd7b, 0x2f7866a2, 0x2554e193, 0xa94e98a6,
                    0x8b74bd25, 0xbb2b3f5f, 0xb0a5fd59, 0x887f9ab6, 0x8159b717, 0x8d5b7b67,
                    0x7cb546bf, 0x41eadca2, 0x16fc1085, 0x0128f8bd, 0xef5c8d89, 0xf96afa4f,
                    0xa8b54885, 0x565ed838, 0xa950fee5, 0xf1c3b0a4, 0xf6fb71e5, 0x4dfd169e,
                    0x82cecc72, 0x66c850e6, 0x7c5ef0ba, 0x960f5214, 0x060e71eb, 0x172a75fc,
                    0x1486835c, 0xbea65344, 0x65b055c9, 0x6a72e410, 0x52241823, 0x25d83041,
                    0x4b40214d, 0xaa8091d2, 0xe0fb010a, 0xe15c6de9, 0x0850973b, 0xdf1e423b,
                    0xe148a237, 0xb87a0c9f, 0x34d4b476, 0x05b803d7, 0x43a86a90, 0x399a4af3,
                    0x96d3a120, 0x0a62f3d9, 0x507962e8, 0xe5bee6d3, 0xda2bb3f7, 0x237664ac,
                    0x7a292823, 0x900bc635, 0x03b29e80, 0xd63f6067, 0xbf8e1716, 0xac25beba,
                    0x350deb62, 0xa99fe031, 0x85eb4f69, 0x937ecd38, 0x7941fda5, 0x44ba67db,
                    0x09117749, 0x38b01827, 0xbcc69c92, 0xb3f772a9, 0xd2859ef0, 0x03398b1f,
                    0x6bbad7b5, 0x74f7989a, 0x1d10b2df, 0x798e0dbf, 0x30d65874, 0x64d24878,
                    0xcd00c0ea, 0xee8a1a0c, 0xc753a279, 0x79e11b41, 0xdb1de3d5, 0x038afaf4,
                    0x9f5c682c, 0x3748d8a3, 0xa9ec54e6, 0xa371275f, 0x1683510f, 0x8e4f9093,
                    0x8f9ab6e1, 0x34c2cfdf, 0x4841cba8, 0x8e0cff2b, 0x0bcc8e6a, 0xdcb71109,
                    0xb5198fec, 0xf1bb7e5c, 0x531aca50, 0xa56a8a3b, 0x6de59862, 0xd41fa113,
                    0xd9cd9578, 0x08f08571, 0xd9a4bb79, 0x2af271f6, 0xcc6dbb8d, 0xc7ec36e3,
                    0x6be1ed30, 0x8164c31c, 0x7c0afc54, 0x1c000000,
                ],
                // mac: 0x0ca12792,
                mac: 0x259299ab,
            },
        ];

        for (i, case) in cases.into_iter().enumerate() {
            let mut mac = ZUCMac::<4>::new(case.count, case.bearer, case.direction == 1, case.ik);
            let msg = case
                .msg
                .into_iter()
                .map(|x| x.to_be_bytes())
                .flatten()
                .collect::<Vec<_>>();
            let tgt = case.mac.to_be_bytes().to_vec();

            mac.write_all(msg.as_slice()).unwrap();
            assert_eq!(tgt, mac.mac(), "case {i} mac failed");
        }
    }
}
