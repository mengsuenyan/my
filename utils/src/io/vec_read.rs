use std::io::Read;

#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct VecRead {
    data: Vec<u8>,
    idx: usize,
}

impl VecRead {
    pub fn new(v: Vec<u8>) -> Self {
        Self { data: v, idx: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.idx == self.data.len()
    }

    pub fn len(&self) -> usize {
        self.data.len() - self.idx
    }
}

impl From<Vec<u8>> for VecRead {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl Read for VecRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let s = &self.data[self.idx..(self.idx + buf.len()).min(self.data.len())];
        buf.copy_from_slice(s);
        self.idx += s.len();
        Ok(s.len())
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        let len = self.data.len();
        buf.append(&mut self.data);
        self.data.shrink_to(0);
        self.idx = 0;
        Ok(len)
    }
}
