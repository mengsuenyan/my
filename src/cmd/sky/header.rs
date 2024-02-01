use super::SkyEncrypt;
use encode::base::Base64;
use encode::Decode;

pub struct SkyEncryptHeader {
    pub flag: [u8; 6],
    pub hash_name_len: u16,
    pub cipher_name_len: u16,
    pub file_name_len: u16,
    pub hash_len: u32,
    pub file_len: u32,
    pub hash_name: Vec<u8>,
    pub cipher_name: Vec<u8>,
    pub file_name: Vec<u8>,
    pub digest: Vec<u8>,
}

impl From<&SkyEncrypt> for SkyEncryptHeader {
    fn from(value: &SkyEncrypt) -> Self {
        Self {
            flag: Self::start_flag(),
            hash_name_len: value.hash_name.as_bytes().len() as u16,
            cipher_name_len: value.cipher_name.as_bytes().len() as u16,
            file_name_len: 0,
            hash_len: 0,
            file_len: 0,
            hash_name: value.hash_name.as_bytes().to_vec(),
            cipher_name: value.cipher_name.as_bytes().to_vec(),
            file_name: vec![],
            digest: vec![],
        }
    }
}

impl TryFrom<&[u8]> for SkyEncryptHeader {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let sl = Self::start_flag().len();
        let min_len = Self::min_len();
        anyhow::ensure!(
            value.len() > min_len,
            "Sky encrypt data as least {} bytes",
            min_len
        );
        anyhow::ensure!(
            Self::start_flag()
                .into_iter()
                .zip(value.iter())
                .all(|(a, &b)| a == b),
            "Sky encrypt data invalid header"
        );
        let hash_name_len = u16::from_be_bytes([value[sl], value[sl + 1]]) as usize;
        let cipher_name_len = u16::from_be_bytes([value[sl + 2], value[sl + 3]]) as usize;
        let file_name_len = u16::from_be_bytes([value[sl + 4], value[sl + 5]]) as usize;
        let hash_len =
            u32::from_be_bytes([value[sl + 6], value[sl + 7], value[sl + 8], value[sl + 9]])
                as usize;
        let file_len = u32::from_be_bytes([
            value[sl + 10],
            value[sl + 11],
            value[sl + 12],
            value[sl + 13],
        ]) as usize;
        let tmp = min_len + hash_name_len + cipher_name_len + file_name_len + hash_len + file_len;
        anyhow::ensure!(
            value.len() >= tmp,
            "Sky encrypt data need to at least {} bytes, but the real is {} bytes",
            tmp,
            value.len()
        );

        Ok(Self {
            flag: Self::start_flag(),
            hash_name_len: hash_name_len as u16,
            cipher_name_len: cipher_name_len as u16,
            file_name_len: file_name_len as u16,
            hash_len: hash_len as u32,
            file_len: file_len as u32,
            hash_name: value[min_len..(min_len + hash_name_len)].to_vec(),
            cipher_name: value
                [(min_len + hash_name_len)..(min_len + hash_name_len + cipher_name_len)]
                .to_vec(),
            file_name: value[(min_len + hash_name_len + cipher_name_len)
                ..(min_len + hash_name_len + cipher_name_len + file_name_len)]
                .to_vec(),
            digest: value[(min_len + hash_name_len + cipher_name_len + file_name_len)
                ..(min_len + hash_name_len + cipher_name_len + file_name_len + hash_len)]
                .to_vec(),
        })
    }
}

impl SkyEncryptHeader {
    // 仅解析header, 不验证数据的总长度
    pub fn only_parse_header_from_b64(b64: &[u8]) -> anyhow::Result<Self> {
        let mut base64 = Base64::new(true);
        let mut value = Vec::with_capacity(1024);
        let mut tmp = &b64[..b64.len().min((Self::min_len() << 1) & !3usize)];
        base64.decode(&mut tmp, &mut value)?;

        let sl = Self::start_flag().len();
        let min_len = Self::min_len();
        anyhow::ensure!(
            value.len() > min_len,
            "Sky encrypt data as least {} bytes",
            min_len
        );
        anyhow::ensure!(
            Self::start_flag()
                .into_iter()
                .zip(value.iter())
                .all(|(a, &b)| a == b),
            "Sky encrypt data invalid header"
        );
        let hash_name_len = u16::from_be_bytes([value[sl], value[sl + 1]]) as usize;
        let cipher_name_len = u16::from_be_bytes([value[sl + 2], value[sl + 3]]) as usize;
        let file_name_len = u16::from_be_bytes([value[sl + 4], value[sl + 5]]) as usize;
        let hash_len =
            u32::from_be_bytes([value[sl + 6], value[sl + 7], value[sl + 8], value[sl + 9]])
                as usize;
        let file_len = u32::from_be_bytes([
            value[sl + 10],
            value[sl + 11],
            value[sl + 12],
            value[sl + 13],
        ]) as usize;
        let header_len = min_len + hash_name_len + cipher_name_len + file_name_len + hash_len;

        let mut tmp = &b64[..b64.len().min((header_len << 1) & !3usize)];
        value.clear();
        base64.decode(&mut tmp, &mut value)?;
        anyhow::ensure!(
            value.len() >= header_len,
            "Sky encrypt data header need to at least {} bytes, but the real is {} bytes",
            header_len,
            value.len()
        );

        Ok(Self {
            flag: Self::start_flag(),
            hash_name_len: hash_name_len as u16,
            cipher_name_len: cipher_name_len as u16,
            file_name_len: file_name_len as u16,
            hash_len: hash_len as u32,
            file_len: file_len as u32,
            hash_name: value[min_len..(min_len + hash_name_len)].to_vec(),
            cipher_name: value
                [(min_len + hash_name_len)..(min_len + hash_name_len + cipher_name_len)]
                .to_vec(),
            file_name: value[(min_len + hash_name_len + cipher_name_len)
                ..(min_len + hash_name_len + cipher_name_len + file_name_len)]
                .to_vec(),
            digest: value[(min_len + hash_name_len + cipher_name_len + file_name_len)
                ..(min_len + hash_name_len + cipher_name_len + file_name_len + hash_len)]
                .to_vec(),
        })
    }

    pub const fn min_len() -> usize {
        6 + 2 + 2 + 2 + 4 + 4
    }

    pub const fn start_flag() -> [u8; 6] {
        [0x1, 0x2, 0x53, 0x6b, 0x79, 0x03]
    }

    pub fn file_offset(&self) -> usize {
        Self::min_len()
            + self.hash_name_len as usize
            + self.cipher_name_len as usize
            + self.file_name_len as usize
            + self.hash_len as usize
    }

    pub fn set_digest(&mut self, h: Vec<u8>) {
        self.hash_len = h.len() as u32;
        self.digest = h;
    }

    pub fn set_data_size(&mut self, s: usize) {
        self.file_len = s as u32;
    }

    pub fn set_file_name(&mut self, file_name: &[u8]) {
        self.file_name_len = file_name.len() as u16;
        self.file_name.clear();
        self.file_name.extend_from_slice(file_name);
    }

    pub fn into_vec(self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1024);
        v.extend(self.flag);
        v.extend(self.hash_name_len.to_be_bytes());
        v.extend(self.cipher_name_len.to_be_bytes());
        v.extend(self.file_name_len.to_be_bytes());
        v.extend(self.hash_len.to_be_bytes());
        v.extend(self.file_len.to_be_bytes());
        v.extend(self.hash_name);
        v.extend(self.cipher_name);
        v.extend(self.file_name);
        v.extend(self.digest);
        v
    }
}
