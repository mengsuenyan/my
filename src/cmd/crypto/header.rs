use crypto_hash::{sha2::SHA256, Digest};
use num_bigint::BigUint;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Debug)]
pub enum Header {
    V1(HeaderV1),
}

#[derive(Clone, Debug)]
pub struct HeaderV1 {
    digest: Vec<u8>,
    fname: Vec<u8>,
    info: Vec<u8>,
}

impl Header {
    pub const MAGIC: [u8; 5] = [0x2, 0x53, 0x6b, 0x79, 0x03];

    pub fn new(info: String) -> Self {
        Self::V1(HeaderV1::new(info))
    }

    pub fn set_info(&mut self, info: String) {
        match self {
            Header::V1(v1) => v1.set_info(info),
        }
    }

    pub fn hash(&mut self, data: &[u8]) {
        match self {
            Header::V1(v1) => v1.hash(data),
        }
    }

    pub fn set_filename(&mut self, path: Option<&Path>) {
        match self {
            Header::V1(v1) => v1.set_filename(path),
        }
    }

    pub fn valid_hash(&self, data: &[u8]) -> bool {
        match self {
            Header::V1(v1) => v1.valid_hash(data),
        }
    }

    pub fn extract_digest(path: &Path) -> Option<Vec<u8>> {
        let Ok(mut f) = File::open(path) else {
            return None;
        };

        let mut buf = Vec::with_capacity(64);
        buf.resize(Self::min_len(), 0u8);
        let Ok(len) = f.read(buf.as_mut_slice()) else {
            return None;
        };

        if len != Self::min_len() || buf[..Self::MAGIC.len()] != Self::MAGIC {
            return None;
        }

        match buf[Self::MAGIC.len()] {
            1 => {
                buf.resize(HeaderV1::min_len(), 0);
                let Ok(len) = f.read(buf.as_mut_slice()) else {
                    return None;
                };

                if len == HeaderV1::min_len() {
                    Some(buf[4..].to_vec())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    const fn min_len() -> usize {
        // magic
        // version
        Self::MAGIC.len() + 1
    }

    pub fn size(&self) -> usize {
        Self::min_len()
            + match self {
                Header::V1(v1) => v1.size(),
            }
    }

    pub fn digest(&self) -> &[u8] {
        match self {
            Header::V1(v1) => v1.digest.as_slice(),
        }
    }

    pub fn file_name(&self) -> &[u8] {
        match self {
            Header::V1(v1) => v1.fname.as_slice(),
        }
    }

    pub fn from_reader<T: Read>(mut reader: T) -> anyhow::Result<Self> {
        let mut data = vec![0u8; Self::min_len()];
        let len = reader.read(data.as_mut_slice())?;

        if len != Self::min_len() {
            anyhow::bail!("invalid header length");
        }

        if data[..Self::MAGIC.len()] != Self::MAGIC {
            anyhow::bail!("invalid header magic");
        }

        match data[Self::MAGIC.len()] {
            1 => Ok(Header::V1(HeaderV1::from_reader(reader)?)),
            v => {
                anyhow::bail!("invalid header version `{v}`");
            }
        }
    }
}

impl HeaderV1 {
    pub fn new(info: String) -> Self {
        Self {
            digest: Vec::default(),
            info: info.into_bytes(),
            fname: Vec::default(),
        }
    }

    fn set_info(&mut self, info: String) {
        self.info = info.into_bytes();
    }

    fn hash(&mut self, data: &[u8]) {
        let digest = if data.is_empty() {
            [0u8; 32].to_vec()
        } else {
            Vec::from(SHA256::digest(data))
        };

        self.digest = digest;
    }

    fn set_filename(&mut self, fname: Option<&Path>) {
        if let Some(Some(Some(s))) = fname.map(|x| x.file_name().map(|x| x.to_str())) {
            self.fname = s.as_bytes().to_vec();
        }
    }

    fn valid_hash(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            false
        } else {
            let d = SHA256::digest(data);
            self.digest == d.as_ref()
        }
    }

    const fn min_len() -> usize {
        // 2: fname length
        // 2: info length
        // 32: digest
        36
    }

    fn size(&self) -> usize {
        Self::min_len() + self.fname.len() + self.info.len()
    }

    fn from_reader<T: Read>(mut reader: T) -> anyhow::Result<Self> {
        let mut data = vec![0u8; Self::min_len()];
        let len = reader.read(data.as_mut_slice())?;

        if len != Self::min_len() {
            anyhow::bail!("invalid header(v1) length");
        }

        let (fname_len, info_len) = (
            u16::from_be_bytes([data[0], data[1]]) as usize,
            u16::from_be_bytes([data[2], data[3]]) as usize,
        );
        let digest = data[4..Self::min_len()].to_vec();

        data.resize(fname_len + info_len, 0);
        let len = reader.read(data.as_mut_slice())?;
        if len != fname_len + info_len {
            anyhow::bail!("invalid header(v1) length format");
        }

        Ok(Self {
            digest,
            fname: data[..fname_len].to_vec(),
            info: data[fname_len..].to_vec(),
        })
    }
}

impl From<Header> for Vec<u8> {
    fn from(value: Header) -> Self {
        let mut v = Vec::with_capacity(128);
        v.extend(Header::MAGIC);

        match value {
            Header::V1(v1) => {
                v.push(1);
                v.extend(Vec::from(v1));
            }
        }

        v
    }
}

impl From<HeaderV1> for Vec<u8> {
    fn from(value: HeaderV1) -> Self {
        let l = value.digest.len() + value.fname.len() + value.info.len();
        let mut v = Vec::with_capacity(4 + l);

        v.extend((value.fname.len() as u16).to_be_bytes());
        v.extend((value.info.len() as u16).to_be_bytes());

        v.extend(value.digest);
        v.extend(value.fname);
        v.extend(value.info);

        v
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Self::from_reader(data)
    }
}

impl TryFrom<&[u8]> for HeaderV1 {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Self::from_reader(data)
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Header::V1(v1) => f.write_fmt(format_args!("{}", v1)),
        }
    }
}

impl Display for HeaderV1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let digest = BigUint::from_bytes_be(self.digest.as_slice());
        let fname = String::from_utf8_lossy(self.fname.as_slice());
        let info = String::from_utf8_lossy(self.info.as_slice());
        f.write_fmt(format_args!(
            "{{digest: {:x}, file: {}, info: {}}}",
            digest, fname, info
        ))
    }
}
