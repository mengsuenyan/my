use utils::Block;
macro_rules! blake2_para {
    ($NAME: ident, $BYTES: literal) => {
        pub struct $NAME {
            pub block: [u8; $BYTES],
        }

        impl $NAME {
            const fn new_inner() -> Self {
                Self {
                    block: [0u8; $BYTES],
                }
            }

            pub const fn new() -> Self {
                let p = Self::new_inner();
                p.fanout(1).depth(1)
            }

            pub const fn digest_len(mut self, len: u8) -> Self {
                self.block[0] = len;
                self
            }

            pub const fn key_len(mut self, len: u8) -> Self {
                self.block[1] = len;
                self
            }

            /// 0: unlimited, 1: sequential mode
            pub const fn fanout(mut self, fanout: u8) -> Self {
                self.block[2] = fanout;
                self
            }

            /// maximal depth,
            /// 255: unlimited, 1: sequential mode
            pub const fn depth(mut self, depth: u8) -> Self {
                self.block[3] = depth;
                self
            }

            /// 0: unlimited, other: sequential mode
            pub const fn leaf_len(mut self, len: u32) -> Self {
                let len = len.to_le_bytes();
                self.block[4] = len[0];
                self.block[5] = len[1];
                self.block[6] = len[2];
                self.block[7] = len[3];
                self
            }
        }
    };
}

blake2_para!(Blake2bPara, 64);
blake2_para!(Blake2sPara, 32);

impl Blake2bPara {
    pub fn to_block(self) -> [u64; 8] {
        let mut block = [0u64; 8];
        self.block
            .chunks_exact(8)
            .zip(block.iter_mut())
            .for_each(|(a, b)| {
                *b = u64::from_le_bytes(Block::to_arr_uncheck(a));
            });
        block
    }

    pub const fn node_offset(mut self, offset: u64) -> Self {
        let len = offset.to_be_bytes();
        self.block[8] = len[0];
        self.block[9] = len[1];
        self.block[10] = len[2];
        self.block[11] = len[3];
        self.block[12] = len[4];
        self.block[13] = len[5];
        self.block[14] = len[6];
        self.block[15] = len[7];
        self
    }

    /// 0: leaves, other: sequential mode
    pub const fn node_depth(mut self, depth: u8) -> Self {
        self.block[16] = depth;
        self
    }

    /// 0: sequential mode
    pub const fn inner_depth(mut self, depth: u8) -> Self {
        self.block[17] = depth;
        self
    }

    pub const fn salt(mut self, salt: [u8; 16]) -> Self {
        let mut i = 0;
        while i < 16 {
            self.block[32 + i] = salt[i];
            i += 1;
        }

        self
    }

    pub const fn custom(mut self, custom: [u8; 16]) -> Self {
        let mut i = 0;
        while i < 16 {
            self.block[48 + i] = custom[i];
            i += 1;
        }
        self
    }
}

impl Blake2sPara {
    pub fn to_block(self) -> [u32; 8] {
        let mut block = [0u32; 8];
        self.block
            .chunks_exact(8)
            .zip(block.iter_mut())
            .for_each(|(a, b)| {
                *b = u32::from_le_bytes(Block::to_arr_uncheck(a));
            });
        block
    }

    pub const fn node_offset(mut self, offset: u64) -> Self {
        let len = offset.to_be_bytes();
        self.block[8] = len[0];
        self.block[9] = len[1];
        self.block[10] = len[2];
        self.block[11] = len[3];
        self.block[12] = len[4];
        self.block[13] = len[5];
        self
    }

    pub const fn node_depth(mut self, depth: u8) -> Self {
        self.block[14] = depth;
        self
    }

    pub const fn inner_depth(mut self, depth: u8) -> Self {
        self.block[15] = depth;
        self
    }

    pub const fn salt(mut self, salt: [u8; 8]) -> Self {
        let mut i = 0;
        while i < 8 {
            self.block[16 + i] = salt[i];
            i += 1;
        }

        self
    }

    pub const fn custom(mut self, custom: [u8; 8]) -> Self {
        let mut i = 0;
        while i < 8 {
            self.block[24 + i] = custom[i];
            i += 1;
        }
        self
    }
}
