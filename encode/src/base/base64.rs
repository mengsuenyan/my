use crate::{Decode, Encode, EncodeError};
use std::io::{Read, Write};

#[derive(Clone)]
pub struct Base64 {
    table: &'static [u8; 64],
}

impl Base64 {
    const BASE64_STD: [u8; 64] = [
        b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O',
        b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd',
        b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's',
        b't', b'u', b'v', b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
        b'8', b'9', b'+', b'/',
    ];

    const BASE64_URL: [u8; 64] = [
        b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O',
        b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd',
        b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's',
        b't', b'u', b'v', b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
        b'8', b'9', b'-', b'_',
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
        let table = if is_std {
            &Self::BASE64_STD
        } else {
            &Self::BASE64_URL
        };

        Self { table }
    }
}

impl Encode for Base64 {
    fn encode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError> {
        let (mut buf, mut olen) = (Vec::with_capacity(1024), 0);

        let ilen = in_data.read_to_end(&mut buf)?;
        let mut itr = buf.chunks_exact(3);

        for d in &mut itr {
            let mut x = [0u8; 4];
            x[0] = self.table[(d[0] >> 2) as usize];
            x[1] = self.table[(((d[0] & 0x3) << 4) | (d[1] >> 4)) as usize];
            x[2] = self.table[(((d[1] & 0xf) << 2) | (d[2] >> 6)) as usize];
            x[3] = self.table[(d[2] & 0x3f) as usize];
            out_data.write_all(&x)?;
            olen += 4;
        }

        if !itr.remainder().is_empty() {
            let mut d = [0u8; 3];
            d[..itr.remainder().len()].copy_from_slice(itr.remainder());

            let mut x = [0u8; 4];
            x[0] = self.table[(d[0] >> 2) as usize];
            x[1] = self.table[(((d[0] & 0x3) << 4) | (d[1] >> 4)) as usize];
            x[2] = self.table[(((d[1] & 0xf) << 2) | (d[2] >> 6)) as usize];
            x[3] = self.table[(d[2] & 0x3f) as usize];
            x.iter_mut()
                .rev()
                .take(8 * (3 - itr.remainder().len()) / 6)
                .for_each(|a| *a = b'=');
            out_data.write_all(&x)?;
            olen += 4;
        }

        Ok((ilen, olen))
    }
}

impl Decode for Base64 {
    fn decode<R: Read, W: Write>(
        &mut self,
        in_data: &mut R,
        out_data: &mut W,
    ) -> Result<(usize, usize), EncodeError> {
        let (mut buf, mut olen) = (Vec::with_capacity(1024), 0);
        let ilen = in_data.read_to_end(&mut buf)?;

        if buf.is_empty() {
            return Ok((0, 0));
        } else if buf.len() % 4 != 0 {
            return Err(EncodeError::InvalidLenInDec(buf.len()));
        }

        for d in buf[0..(buf.len() - 4)].chunks_exact(4) {
            let mut c = [0u8; 4];
            for (a, &b) in c.iter_mut().zip(d) {
                *a = self.code_to_idx(b)?;
            }

            let x = [
                (c[0] << 2) | (c[1] >> 4),
                (c[1] << 4) | (c[2] >> 2),
                (c[2] << 6) | c[3],
            ];
            out_data.write_all(&x)?;
            olen += 3;
        }

        let (mut cnt, mut c) = (0, [0u8; 4]);
        for &a in buf.iter().rev().take(4) {
            if a == b'=' {
                cnt += 1;
            } else {
                break;
            }
        }

        if cnt == 4 || cnt == 3 {
            return Err(EncodeError::InvalidBaseCodeInDec('='));
        } else {
            for (a, &b) in c
                .iter_mut()
                .take(4 - cnt)
                .zip(buf.iter().skip(buf.len() - 4))
            {
                *a = self.code_to_idx(b)?;
            }

            let x = [
                (c[0] << 2) | (c[1] >> 4),
                (c[1] << 4) | (c[2] >> 2),
                (c[2] << 6) | c[3],
            ];
            let tmp = 3 - (cnt * 6 + 7) / 8;
            out_data.write_all(&x[..tmp])?;
            olen += tmp;
        }

        Ok((ilen, olen))
    }
}

#[cfg(test)]
mod tests {
    use crate::base::base64::Base64;
    use crate::{Decode, Encode};

    fn cases() -> Vec<(String, String, String)> {
        [
            ("5yc2y3mUTo", "NXljMnkzbVVUbw==", "NXljMnkzbVVUbw=="),
            ("neTazviGodU", "bmVUYXp2aUdvZFU=", "bmVUYXp2aUdvZFU="),
            ("GhA3r8k4uGp1", "R2hBM3I4azR1R3Ax", "R2hBM3I4azR1R3Ax"),
            (
                "feSNIHXfV0uBQ",
                "ZmVTTklIWGZWMHVCUQ==",
                "ZmVTTklIWGZWMHVCUQ==",
            ),
            (
                "JzyQdbtKQiGurS",
                "Snp5UWRidEtRaUd1clM=",
                "Snp5UWRidEtRaUd1clM=",
            ),
            (
                "qSLEUzPkw29AH03",
                "cVNMRVV6UGt3MjlBSDAz",
                "cVNMRVV6UGt3MjlBSDAz",
            ),
            (
                "odYoeYTJhfjx48P7",
                "b2RZb2VZVEpoZmp4NDhQNw==",
                "b2RZb2VZVEpoZmp4NDhQNw==",
            ),
            (
                "I4j2W1ITd6m6yYWiN",
                "STRqMlcxSVRkNm02eVlXaU4=",
                "STRqMlcxSVRkNm02eVlXaU4=",
            ),
            (
                "gYoakxkUB4ninjvXqo",
                "Z1lvYWt4a1VCNG5pbmp2WHFv",
                "Z1lvYWt4a1VCNG5pbmp2WHFv",
            ),
            (
                "sA2dpicGBj47eyeXdpv",
                "c0EyZHBpY0dCajQ3ZXllWGRwdg==",
                "c0EyZHBpY0dCajQ3ZXllWGRwdg==",
            ),
            (
                "bAGLpoDWBlrAlwUhXl34",
                "YkFHTHBvRFdCbHJBbHdVaFhsMzQ=",
                "YkFHTHBvRFdCbHJBbHdVaFhsMzQ=",
            ),
        ]
        .into_iter()
        .map(|(x, y, z)| (x.to_string(), y.to_string(), z.to_string()))
        .collect::<Vec<_>>()
    }

    #[test]
    fn encode_std() {
        for (i, (case, std, _)) in cases().into_iter().enumerate() {
            let mut base = Base64::new(true);
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
            let mut base = Base64::new(false);
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
