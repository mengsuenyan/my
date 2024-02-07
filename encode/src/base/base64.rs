use crate::{Decode, Encode, EncodeError};
use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::mpsc::TryRecvError,
};

#[derive(Clone)]
pub struct Base64 {
    table: &'static [u8; 64],
    dtable: &'static [u8; 128],
}

impl Base64 {
    const BASE64_STD: [u8; 64] = [
        b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O',
        b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd',
        b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's',
        b't', b'u', b'v', b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
        b'8', b'9', b'+', b'/',
    ];

    const BASE64_STD_D: [u8; 128] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0,
    ];
    const BASE64_URL_D: [u8; 128] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 63, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0,
    ];

    const BASE64_URL: [u8; 64] = [
        b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O',
        b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'a', b'b', b'c', b'd',
        b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r', b's',
        b't', b'u', b'v', b'w', b'x', b'y', b'z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
        b'8', b'9', b'-', b'_',
    ];

    /// `is_std`使用标准码表, 还是URL版本码表
    pub fn new(is_std: bool) -> Self {
        let (table, dtable) = if is_std {
            (&Self::BASE64_STD, &Self::BASE64_STD_D)
        } else {
            (&Self::BASE64_URL, &Self::BASE64_URL_D)
        };

        Self { table, dtable }
    }

    fn encode_inner<W: Write>(
        table: &'static [u8; 64],
        chunks: &[u8],
        data: &mut W,
    ) -> Result<usize, EncodeError> {
        let mut olen = 0;
        for d in chunks.chunks_exact(3) {
            let mut x = [0u8; 4];
            x[0] = table[(d[0] >> 2) as usize];
            x[1] = table[(((d[0] & 0x3) << 4) | (d[1] >> 4)) as usize];
            x[2] = table[(((d[1] & 0xf) << 2) | (d[2] >> 6)) as usize];
            x[3] = table[(d[2] & 0x3f) as usize];
            olen += data.write(&x)?;
        }
        Ok(olen)
    }

    fn decode_inner<W: Write>(
        table: &'static [u8; 128],
        chunks: &[u8],
        data: &mut W,
    ) -> Result<usize, EncodeError> {
        let mut olen = 0;
        for d in chunks.chunks_exact(4) {
            let c = [
                table[d[0] as usize],
                table[d[1] as usize],
                table[d[2] as usize],
                table[d[3] as usize],
            ];

            let x = [
                (c[0] << 2) | (c[1] >> 4),
                (c[1] << 4) | (c[2] >> 2),
                (c[2] << 6) | c[3],
            ];
            olen += data.write(&x)?;
        }
        Ok(olen)
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
        let len = buf.len();
        let remainder = buf[(len - len % 3)..len].to_vec();
        buf.truncate(len - len % 3);

        if buf.len() > (1 << 29) {
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::scope::<'_, _, Result<(), EncodeError>>(|s| {
                let l = ((buf.len() / 3) / num_cpus::get().max(1)).max(1) * 3;
                for (i, chunks) in buf.chunks(l).enumerate() {
                    let sender = sender.clone();
                    let table = self.table;
                    s.spawn(move || {
                        let mut buf = Vec::with_capacity(chunks.len() * 4 / 3 + 105);
                        let _ = Self::encode_inner(table, chunks, &mut buf).unwrap();
                        sender.send((i, buf)).unwrap();
                    });
                }

                drop(sender);
                let (mut cursor, mut recv_buf) = (0, HashMap::with_capacity(1024));
                loop {
                    match receiver.try_recv() {
                        Ok((idx, data)) => {
                            if idx == cursor {
                                olen += out_data.write(&data)?;
                                cursor += 1;
                            } else {
                                recv_buf.insert(idx, data);
                            }
                        }
                        Err(TryRecvError::Disconnected) => {
                            if recv_buf.is_empty() {
                                break;
                            }
                        }
                        _ => {}
                    }

                    if let Some(data) = recv_buf.remove(&cursor) {
                        olen += out_data.write(&data)?;
                        cursor += 1;
                    }
                }

                Ok(())
            })?;
        } else {
            olen += Self::encode_inner(self.table, &buf, out_data)?;
        }

        if !remainder.is_empty() {
            let mut d = [0u8; 3];
            d[..remainder.len()].copy_from_slice(&remainder);

            let mut data = Vec::<u8>::with_capacity(4);
            olen += Self::encode_inner(self.table, &d, &mut data)?;
            data.iter_mut()
                .rev()
                .take(8 * (3 - remainder.len()) / 6)
                .for_each(|a| *a = b'=');
            out_data.write_all(&data)?;
        }
        out_data.flush()?;

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

        let remainer = buf[buf.len().saturating_sub(4)..].to_vec();
        buf.truncate(buf.len().saturating_sub(4));

        if buf.len() > (1 << 29) {
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::scope::<'_, _, Result<(), EncodeError>>(|s| {
                let l = ((buf.len() / 4) / num_cpus::get().max(1)).max(1) * 4;
                for (i, chunks) in buf.chunks(l).enumerate() {
                    let sender = sender.clone();
                    let table = self.dtable;
                    s.spawn(move || {
                        let mut buf = Vec::with_capacity(chunks.len() * 3 / 4 + 105);
                        let _ = Self::decode_inner(table, chunks, &mut buf).unwrap();
                        sender.send((i, buf)).unwrap();
                    });
                }

                drop(sender);
                let (mut cursor, mut recv_buf) = (0, HashMap::with_capacity(1024));
                loop {
                    match receiver.try_recv() {
                        Ok((idx, data)) => {
                            if idx == cursor {
                                olen += out_data.write(&data)?;
                                cursor += 1;
                            } else {
                                recv_buf.insert(idx, data);
                            }
                        }
                        Err(TryRecvError::Disconnected) => {
                            if recv_buf.is_empty() {
                                break;
                            }
                        }
                        _ => {}
                    }

                    if let Some(data) = recv_buf.remove(&cursor) {
                        olen += out_data.write(&data)?;
                        cursor += 1;
                    }
                }

                Ok(())
            })?;
        } else {
            olen += Self::decode_inner(self.dtable, &buf, out_data)?;
        }

        let (mut cnt, mut c) = (0, [0u8; 4]);
        for &a in remainer.iter().rev() {
            if a == b'=' {
                cnt += 1;
            } else {
                break;
            }
        }

        if cnt == 4 || cnt == 3 {
            return Err(EncodeError::InvalidBaseCodeInDec('='));
        } else {
            for (a, b) in c.iter_mut().take(4 - cnt).zip(remainer) {
                *a = self.dtable[b as usize];
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
        out_data.flush()?;

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
