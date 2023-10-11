use crate::{Decode, Encode, EncodeError};
use std::io::{Read, Write};

#[derive(Clone)]
pub struct Base32 {
    buf: Vec<u8>,
    table: &'static [u8; 32],
}

impl Base32 {
    const BASE32_STD: [u8; 32] = [
        b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O',
        b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'2', b'3', b'4', b'5',
        b'6', b'7',
    ];
    const BASE32_URL: [u8; 32] = [
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E',
        b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P', b'Q', b'R', b'S', b'T',
        b'U', b'V',
    ];

    fn code_to_idx(&self, code: u8) -> Result<u8, EncodeError> {
        self.table
            .iter()
            .enumerate()
            .find(|x| *x.1 == code)
            .map(|x| x.0 as u8)
            .ok_or(EncodeError::InvalidBaseCodeInDec(char::from(code)))
    }

    /// `is_std`使用标准码表, 还是URL版本码表
    pub fn new(is_std: bool) -> Self {
        Self::with_capacity(200, is_std)
    }

    /// 指定缓存大小
    pub fn with_capacity(cap: usize, is_std: bool) -> Self {
        let cap = cap + (5 - cap % 5);
        let x = vec![0; cap.max(200)];
        Self {
            buf: x,
            table: if is_std {
                &Self::BASE32_STD
            } else {
                &Self::BASE32_URL
            },
        }
    }
}

impl Encode for Base32 {
    fn encode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError> {
        macro_rules! code {
            ($D: ident) => {
                [
                    self.table[($D[0] >> 3) as usize],
                    self.table[((($D[0] & 0x7) << 2) | ($D[1] >> 6)) as usize],
                    self.table[(($D[1] >> 1) & 0x1f) as usize],
                    self.table[((($D[1] & 0x1) << 4) | ($D[2] >> 4)) as usize],
                    self.table[((($D[2] & 0xf) << 1) | ($D[3] >> 7)) as usize],
                    self.table[(($D[3] >> 2) & 0x1f) as usize],
                    self.table[((($D[3] & 0x3) << 3) | ($D[4] >> 5)) as usize],
                    self.table[($D[4] & 0x1f) as usize],
                ]
            };
        }

        let (mut ilen, mut idx) = (0, 0);

        loop {
            let l = in_data.read(&mut self.buf[idx..])?;

            if l == 0 {
                break;
            }

            let up_bound = idx + l;
            let mut itr = self.buf[..up_bound].chunks_exact(5);
            for d in &mut itr {
                let x = code!(d);
                out_data.write_all(x.as_slice())?;
            }

            idx = itr.remainder().len() % 5;
            if idx != 0 {
                self.buf[..up_bound].rotate_right(idx);
            }

            ilen += l;
        }

        if idx != 0 {
            self.buf.iter_mut().take(5).skip(idx).for_each(|a| *a = 0);
            let d = &self.buf[..5];
            let mut x = code!(d);
            x.iter_mut()
                .rev()
                .take(8 * (5 - idx) / 5)
                .for_each(|a| *a = b'=');
            out_data.write_all(x.as_slice())?;
        }

        out_data.flush()?;
        Ok((ilen, ((ilen + 4) / 5) * 8))
    }
}

impl Decode for Base32 {
    fn decode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError> {
        let (mut ilen, mut olen, mut idx, mut is_eq_checked) = (0, 0, 0, false);
        let up = self.buf.len() - self.buf.len() % 8;

        loop {
            let l = in_data.read(&mut self.buf[idx..up])?;
            if l == 0 {
                break;
            } else if is_eq_checked {
                return Err(EncodeError::InvalidLenInDec(ilen + l));
            }
            ilen += l;

            let mut itr = self.buf[..(idx + l)].chunks_exact(8);
            for c in &mut itr {
                let (mut d, mut eq_cnt) = ([0u8; 8], 0);

                if c[7] == b'=' {
                    for x in c.iter().rev() {
                        if *x != b'=' {
                            break;
                        }
                        eq_cnt += 1;
                    }

                    if eq_cnt == 8 || eq_cnt == 7 || eq_cnt == 5 || eq_cnt == 2 {
                        return Err(EncodeError::InvalidBaseCodeInDec('='));
                    }

                    for (a, &b) in d.iter_mut().take(8 - eq_cnt).zip(c) {
                        *a = self.code_to_idx(b)?;
                    }
                    is_eq_checked = true;
                } else {
                    for (a, &b) in d.iter_mut().zip(c) {
                        *a = self.code_to_idx(b)?;
                    }
                }

                d[0] = (d[0] << 3) | (d[1] >> 2);
                d[1] = ((d[1] & 0x3) << 6) | (d[2] << 1) | (d[3] >> 4);
                d[2] = ((d[3] & 0xf) << 4) | (d[4] >> 1);
                d[3] = (d[4] << 7) | (d[5] << 2) | (d[6] >> 3);
                d[4] = ((d[6] & 0x7) << 5) | d[7];

                if eq_cnt == 0 {
                    out_data.write_all(&d[..5])?;
                    olen += 5;
                } else {
                    let tmp = 5 - ((eq_cnt * 5) + 7) / 8;
                    out_data.write_all(&d[..tmp])?;
                    olen += tmp;
                }
            }

            idx = itr.remainder().len() % 8;
        }

        if idx != 0 {
            Err(EncodeError::InvalidLenInDec(ilen))
        } else {
            out_data.flush()?;
            Ok((ilen, olen))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::base::base32::Base32;
    use crate::{Decode, Encode};

    fn cases() -> Vec<(String, String, String)> {
        [
            ("tnhlKbedAU", "ORXGQ3CLMJSWIQKV", "EHN6GR2BC9IM8GAL"),
            (
                "hDYBvrmng48",
                "NBCFSQTWOJWW4ZZUHA======",
                "D125IGJME9MMSPPK70======",
            ),
            (
                "KBkNkG3xQSyX",
                "JNBGWTTLI4ZXQUKTPFMA====",
                "9D16MJJB8SPNGKAJF5C0====",
            ),
            (
                "jS4pKWGpipTj7",
                "NJJTI4CLK5DXA2LQKRVDO===",
                "D99J8S2BAT3N0QBGAHL3E===",
            ),
            (
                "glLX4biF1XqnBi",
                "M5WEYWBUMJUUMMKYOFXEE2I=",
                "CTM4OM1KC9KKCCAOE5N44Q8=",
            ),
            (
                "kj3ZFcVxN3ouYKU",
                "NNVDGWSGMNLHQTRTN52VSS2V",
                "DDL36MI6CDB7GJHJDTQLIIQL",
            ),
            (
                "32a7wxinSt98Lfpa",
                "GMZGCN3XPBUW4U3UHE4EYZTQME======",
                "6CP62DRNF1KMSKRK74S4OPJGC4======",
            ),
            (
                "blRdm53pjvoZvnOqp",
                "MJWFEZDNGUZXA2TWN5NHM3SPOFYA====",
                "C9M54P3D6KPN0QJMDTD7CRIFE5O0====",
            ),
            (
                "TJeozoBeK2ernN3CFA",
                "KRFGK332N5BGKSZSMVZG4TRTINDEC===",
                "AH56ARRQDT16AIPICLP6SJHJ8D342===",
            ),
            (
                "RGmMZlAA0TrsYiTK67G",
                "KJDW2TK2NRAUCMCUOJZVS2KUJM3DORY=",
                "A93MQJAQDH0K2C2KE9PLIQAK9CR3EHO=",
            ),
            (
                "fniDoV9IcZTFRiVcBQa0",
                "MZXGSRDPKY4USY22KRDFE2KWMNBFCYJQ",
                "CPN6IH3FAOSKIOQQAH354QAMCD152O9G",
            ),
        ]
        .into_iter()
        .map(|(x, y, z)| (x.to_string(), y.to_string(), z.to_string()))
        .collect::<Vec<_>>()
    }

    #[test]
    fn encode_std() {
        for (i, (case, std, _)) in cases().into_iter().enumerate() {
            let mut base = Base32::new(true);
            let mut buf = vec![];
            let (ilen, olen) = base.encode(&mut case.as_bytes(), &mut buf).unwrap();
            assert_eq!(
                ilen,
                case.as_bytes().len(),
                "case {i} input data len not matched in encode"
            );
            assert_eq!(
                olen,
                std.as_bytes().len(),
                "case {i} output data len not matched in encode"
            );
            assert_eq!(std.as_bytes(), buf, "case {i} failed");

            buf.clear();
            let (ilen, olen) = base.decode(&mut std.as_bytes(), &mut buf).unwrap();
            assert_eq!(
                ilen,
                std.as_bytes().len(),
                "case {i} input data len not matched in decode"
            );
            assert_eq!(
                olen,
                case.as_bytes().len(),
                "case {i} output data len not matched in decode"
            );
            assert_eq!(case.as_bytes(), buf, "case {i} failed");
        }
    }

    #[test]
    fn encode_url() {
        for (i, (case, _, url)) in cases().into_iter().enumerate() {
            let mut base = Base32::new(false);
            let mut buf = vec![];
            let (ilen, olen) = base.encode(&mut case.as_bytes(), &mut buf).unwrap();
            assert_eq!(
                ilen,
                case.as_bytes().len(),
                "case {i} input data len not matched in encode"
            );
            assert_eq!(
                olen,
                url.as_bytes().len(),
                "case {i} output data len not matched in encode"
            );
            assert_eq!(url.as_bytes(), buf, "case {i} failed");

            buf.clear();
            let (ilen, olen) = base.decode(&mut url.as_bytes(), &mut buf).unwrap();
            assert_eq!(
                ilen,
                url.as_bytes().len(),
                "case {i} input data len not matched in decode"
            );
            assert_eq!(
                olen,
                case.as_bytes().len(),
                "case {i} output data len not matched in decode"
            );
            assert_eq!(case.as_bytes(), buf, "case {i} failed");
        }
    }
}
