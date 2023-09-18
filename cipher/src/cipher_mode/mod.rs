//! # Recommendation for Block Cipher Mode of Operation: Method and Techniques
//!
//! [Block Cipher Techniques](https://csrc.nist.gov/Projects/block-cipher-techniques/BCM/current-modes)<br>
//! [NIST 800-38A, Recommendation for Block Cipher Modes of operation Methods and Techniques](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)<br>
//! [NIST 800-38A-add, Three Variants of Ciphertext Stealing for CBC mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a-add.pdf)
//!
//! 笔记: `分组加密工作模式.md` <br>
//! <br>
//! ## The Electronic Codebook Mode(ECB)
//!
//! $$
//! C_j = Encrypt(P_j), j = 1...n
//!
//! P_j = Decrypt(C_j), j = 1...n
//! $$
//!
//! 给定的密钥, 每个明文块和密文块一一对应(如果不期待使用这一特性, 不应该使用ECB模式), 加解密都可并行. <br>
//! <br>
//! ## The Cipher Block Chaining Mode(CBC)
//!
//! 给定初始向量IV, IV可以不保密, 但是**它必须是不可预测的(unpredictable)**. <br>
//!
//! $$
//! C_1 = Encrypt(P_1 \xor IV); C_j = Encrypt(P_j \xor C_{j-1}), j = 2...n
//!
//! P_1 = Decrypt(C_1) \xor IV; P_j = Decrypt(C_j) \xor C_{j-1}, j = 2...n
//! $$
//!
//! 在CBC模式中, 加密每个明文块依赖前一个密文输出, 故Encrypt无法并行. 但Decrypt是可以并行的. <br>
//! <br>
//! ## The Cipher Feedback Mode(CFB)
//!
//! 记有初始向量IV(IV可以不保密, 但是**它必须是不可预测的(unpredictable)**.), b是分组加密函数的分组位大小, s是给定的整数参数满足$1 \le s \le b$. <br>
//!
//! $$
//! I_1 = IV; I_j = LSB_{b-s}(I_{j-1} | C'_{j-1}, j = 2...n; O_j = Encrypt(I_j), j = 1...n; C'_j = P'_j \xor MSB_{s}(O_j), j = 1...n;
//!
//! I_1 = IV; I_j = LSB_{b-s}(I_{j-1}) | C'_{j-1}, j = 2...n; O_j = Encrypt(I_j), j = 1...n; P'_j = C'_j \xor MSB_{s}(O_j), j = 1...n;
//! $$
//!
//! 在CFB模式中, 当前加密的输入块数据是上一次的加密输出和上一次的加密输入的结合, 即当前加密输出反馈到输出结合得到下一个加密的输入. <br>
//! 每次加密依赖前一次的加密输出, 故Encrypt无法并行. Decrypt的输入是依赖前一次的输入, 当每次加密的输入$IV_j$都计算出来的前提下, Decrypt是可并行的. <br>
//! <br>
//! ## The Output Feedback Mode(OFB)
//!
//! 给定初始向量IV, **其需要是一个nonce值**. 即对于给定的密钥, 每次执行OFB模式时, $IV$都需要是独一无二的(unique), 且需要是保密的. <br>
//!
//! $$
//! I_1 = IV; I_j = O_{j-1}, j = 2...n; O_j = Encrypt(I_j), C_j = P_j \xor O_j, j = 1...n-1; C'_n = P'_n \xor MSB_u(O_n);
//!
//! I_1 = IV; I_j = O_{j-1}, j = 2...n; O_j = Encrypt(I_j), P_j = C_j \xor O_j, j = 1...n-1; P'_n = C'_n \xor MSB_u(O_n);
//! $$
//!
//! 从OFB的工作方式可以看出, 每次加解密都依赖于前一次的加解密, 因此加解密都是无法并行的. 另外, $IV$的保密性随机性需要保证,
//! 否则某个明文泄露则之后的密文都会计算出来, 从而之后的明文都会解密出来. <br>
//! <br>
//! ## The Counter Mode(CTR)
//!
//! 给定计数器, 其生成的计数值$T_i$每个都需要是相异的, 且需要是保密的. <br>
//!
//! $$
//! O_j = Encrypt(T_j), j = 1...n; C_j = P_j \xor O_j, j = 1...n-1; C'_n = P'_n \xor MSB_u(O_n);
//!
//! O_j = Encrypt(T_j), j = 1...n; P_j = C_j \xor O_j, j = 1...n-1; P'_n = C'_n \xor MSB_u(O_n);
//! $$
//!
//! 在CTR工作模式中, 如果每个$T_i$能提前计算出来, 那么加解密可以并行.
//!

mod padding;
pub use padding::{BlockPadding, DefaultPadding, EmptyPadding};

mod ecb;
pub use ecb::{AES128Ecb, AES192Ecb, AES256Ecb, AESEcb, ECB};
