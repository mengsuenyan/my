use std::ops::{Deref, DerefMut};
#[cfg(feature = "sec-zeroize")]
use zeroize::Zeroize;

#[derive(Default, Clone, Debug)]
pub struct Block {
    data: Vec<u8>,
}

impl Block {
    pub const fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_arr<const N: usize>(&self) -> Option<&[u8; N]> {
        if self.data.len() == N {
            unsafe { Some(&*(self.data.as_ptr() as *const [u8; N])) }
        } else {
            None
        }
    }

    pub const fn as_arr_ref<const N: usize>(data: &[u8]) -> Option<&[u8; N]> {
        if data.len() == N {
            unsafe { Some(&*(data.as_ptr() as *const [u8; N])) }
        } else {
            None
        }
    }

    pub const fn as_arr_ref_uncheck<const N: usize>(data: &[u8]) -> &[u8; N] {
        unsafe { &*(data.as_ptr() as *const [u8; N]) }
    }

    pub const fn to_arr<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
        if data.len() == N {
            unsafe { Some((data.as_ptr() as *const [u8; N]).read()) }
        } else {
            None
        }
    }

    /// Undefined: <br>
    /// 如果`data.len() != N`可能会造成不可知的错误, 如内存越界访问等.
    pub const fn to_arr_uncheck<const N: usize>(data: &[u8]) -> [u8; N] {
        unsafe { (data.as_ptr() as *const [u8; N]).read() }
    }
}

impl AsRef<Vec<u8>> for Block {
    fn as_ref(&self) -> &Vec<u8> {
        &self.data
    }
}

impl AsMut<Vec<u8>> for Block {
    fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

impl Deref for Block {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data.as_slice()
    }
}

impl DerefMut for Block {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.as_mut_slice()
    }
}

#[cfg(feature = "sec-zeroize")]
impl Zeroize for Block {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(feature = "sec-zeroize-drop")]
impl Drop for Block {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<&[u8]> for Block {
    fn from(value: &[u8]) -> Self {
        Self {
            data: value.to_vec(),
        }
    }
}

impl<A> Extend<A> for Block
where
    Vec<u8>: Extend<A>,
{
    fn extend<T: IntoIterator<Item = A>>(&mut self, iter: T) {
        self.data.extend(iter)
    }
}
