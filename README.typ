#show heading: set text(fill: blue)
#set page(paper: "a4", numbering: "1")
#set block(spacing: 2em)
// #set par(leading: 1em)
#set list(marker: ([-], [•], [.]))
#set heading(numbering: (..it) => {
  it.pos().map(x => {str(x)}).join(".")
}, supplement: "Chapter")

#outline(title: [目录], indent: 1em)

= TODO

- 当rust支持泛型impl中支持常数参数时, 修改`BlockEncryptX/BlockDecryptX`的实现;
- 程序中的一些密钥内存值没有zerozize销毁掉;

= crypto_hash

主要的trait:
- `Digest`: 摘要算法需要实现的trait;
  - `DigestX`: `Digext`动态派发版本. 另, 实现`XOF`的算法也可实现该trait;
- `XOF`: extendable output function算法实现的trait;
  - `XOFx`: `XOF`的动态派发版本;

哈希算法实现, 支持的哈希算法有:
- SHA2: 实现标准*FIPS 180-4*;
  - SHA1, SHA224, SHA256, SHA384, SHA512, SHA512t, SHA512T224, SHA512T256, SHA512tInner;
    - SHA224是SHA256摘要截断到224位;
    - SHA384是SHA512摘要截断到384位;
    - SHA512T224/SHA512T256是等价于SHA512t<24>/SHA512t<25>
- SHA3: 实现标准*FIPS 202*;
  - `SHA3<const Rate: usize, const OutputLen>`: 所有SHA3函数通用底层实现, 可自己通过指定rate和output len自定义非标准的sha3示例;
  - Digest算法: SHA224, SHA256, SHA384, SHA512;
  - XOF算法: SHAKE128, SHAKE256, RawSHAKE128, RawSHAKE256;
    - XOF算法实现了`DigestX` trait, 另还定义了诸如SHAKE128Wrapper的泛型分装实现了`Digest` trait;
- CSHAKE: 实现标准*SP 800-184*, 有SHA3派生的一些函数;
  - XOF: `CSHAKE<const Rate: usize>`: 底层`SHA3<Rate,0>`, 指定摘要长度/功能函数名/自定义字串;
    - CSHAKE128, CSHAKE256: `CSHAKE<R>`特化, `CSHAKE<168>/CSHAKE<136>`;
  - XOF/MAC: `KMAC<Rate>/KMACXof<Rate>`是CSHAKE的变体, 功能函数名指定为了"KAMC", 指定输出长度/密钥/自定字串. 这里实现为了XOF, 在@cipher 中实现MAC消息认证码;
    - KMAC128, KMAC256, KMACXof128, KMACXof256;
- SM3: 实现标准*GM/T 0004-2012*;
  - SM3摘要长度256;
- BLKAE2: 实现标准*#link("https://www.blake2.net/")[BLAKE2]*或*RFC7693*;
  - XOF: BLAKE2b;
    - Digest: BLAKE2b128, BLAKE2b224, BLAKE2b256, BLAKE2b384, BLAKE2b512;
  - XOF:BLAKE2s;
    - Digest: BLAKE2s128, BLAKE2s224, BLAKE2s256;

= cipher <cipher>

主要的trait:
- `BlockCipher`: 分组密码学, 动态派发版本`BlockCipherX`;
  - `BlockEncrypt/BlockDecrypt`: 分组加密解密;
  - `BlockEncryptX/BlockDecryptX`: 动态派发版本
  - `BlockDecrypt`: 分组解密, 动态派发版本`BlockDecryptX`;
- `Cipher`: 加密算法都实现了该trait;
  - `Encrypt/Decrypt`: 加密解密;
- `StreamCipher`: 流加密算法, 动态派发版本`StreamCipherX`;
  - `StreamEncrypt/StreamDecrypt`: 流加密解密;
  - `StreamEncryptX/StreamDecryptX`: 动态派发版本;
- `Signer`: 签名算法;
  - `Sign/Verify`: 签名验证;
- `AuthenticationCipher`: 认证加密算法, 动态派发版本`AuthenticatinCipherX`;
- `MAC`: 消息认证码;
- `PRF`: 伪随机函数;
- `KDF`: 密钥派生函数;

== BlockCipher

支持的分组加密算法有:
- AES: 实现标准*FIPS 197*;
  - AES, AES128, AES192, AES256;
- SM4: 实现标准*GM/T 0002-2012*;
  - 密钥128位;
- RSA OAEP: 实现标准*PKCS v2.2*. 虽然不是严格的分组加密, 但实现了`BlockeEncryptX/BlockDecryptX`
  - OAEPEncrypt, OAEPDecrypt.
- RSA PKCS1: 实现标准*PKCS v2.2*. 虽然不是严格的分组加密, 但实现了`BlockeEncryptX/BlockDecryptX`
  - PKCS1Encrypt, PKCS1Decrypt;

== Signer

- RSA PSS: 实现标准*PKCS v2.2*;
  - PSSSign, PSSVerify;
- ECDSA: 实现标准*FIPS 186-5*;
  - short weierstrass曲线: P224, P256, P384, P521;

== AuthenticationCipher

- CCM: Counter with Cipher Block Chaining-Message Authentication Code, 实现标准*SP 800-38C*;
  - `CCM<BlockEncryptX>`: 指定实现了`BlockEncryptX`trait的加密算法;
    - 特化版本: AES128Ccm, AES192Ccm, AES256Ccm, AESCcm;
- GCM: Galois/Counter Mode, 实现标准*SP 800-38D*;
  - `GCM<BlockEncryptX>`, 指定实现了`BlockEncryptX`的算法;
    - 特化版本: AES128Gcm, AES192Gcm, AES256Gcm, AESGcm;
  - `GCMStream<BlockEncryptX>`, 指定实现了`BlockEncryptX`算法, 和`GCM`一样的, 只不过另外实现了`StreamCipher`接口;
    - 特化版本: AES128GcmStream, AES192GcmStream, AES256GcmStream, AESGcmStream;

== StreamCipher

- GCM: Gaslois/Counter Mode, 实现标准*SP 800-38D*;
  - `GCMStream<BlockEncrypt>`, 指定实现了`BlockEncryptX`算法, 其还实现了`AuthenticationCipher`接口;
    - 特化版本: AES128GcmStream, AES192GcmStream, AES256GcmStream, AESGcmStream;
- ZUC: 祖冲之流加密算法, 实现标准*GM/T 0001-2012*;
  - ZUC;
- 分组加密的工作模式: 实现标准*SP 800-38A*;
  - `ECB<P, E>`: Electronic codebook mode, `P`指定填充方法, `E`指定分组加密算法;
    - 特化版本: AES128Ecb, AES192Ecb, AES256Ecb, AESEcb;
  - `CBC<P, E>`: Cipher block chaining mode,`P`指定填充方法, `E`指定分组加密算法;
    - 特化版本: AES128Cbc, AES192Cbc, AES256Cbc, AESCbc;
  - `CFB<P, E>`: Cipher feedback mode, `P`指定填充方法, `E`指定分组加密算法;
    - 特化版本: AES128Cfb, AES192Cfb, AES256Cfb, AESCfb;
  - `OFB<E>`: Output feedback mode, `E`指定分组加密算法;
    - 特化版本: AES128Ofb, AES192Ofb, AES256Ofb, AESOfb;
  - `CTR<C, E>`: Counter mode, `C`指定计数器, `E`指定分组加密算法;
    - 特化版本: AES128Ctr, AES192Ctr, AES256Ctr, AESCtr;
  - `CBCCs<E>`: Cipher block chaining ciphertext stealing, `E`指定分组加密算法. 实现标准: *SP 800-38A-add*;
    - CBCCsMode: 分为三种模式CbcCs1, CbcCs2, CbcCs3, 后两种模式都是以CbcCs1为基础实现的;
    - 特化版本: AES128CbcCs, AES192CbcCs, AES256CbcCs, AESCbcCs;
- RSA: 实现标准*PCKS v2.2*;
  - OAEPDecryptStream/OAEPEncryptStream/PKCS1EncryptStream/PKCS1DecryptStream;

== MAC

- ZUC: 祖冲之消息认证码, 实现标准*GM/T 0001-2012*;
  - `ZUCMac<const N: usize>`: 规范定义的输出是32位, 即`ZUCStdMac = ZUCMac<4>`. 这里给出扩展, 输出`N`字节的MAC;
   - 特化版本: ZUCStdMac, 标准定义的MAC实现;
- CMAC: 基于分组加密的消息认证码, 实现标准*SP 800-38B*;
  - `CMAC<BlockEncryptX>`;
- HMAC: 基于哈希密钥的消息认证码, 实现标准*FIPS 198-1*;
  - `HMAC<H: Digest>`: `H`指定哈希算法, 输出消息认证码长度既是`H`的摘要长度;
- CSHAKE: 实现标准*SP 800-184*, 有SHA3派生的一些函数;
  - `KMAC<Rate>`;
  - `KMACXof<Rate>`;

== PRF

- HMAC: `HMAC<D>`实现了`PRF`;

== KDF

- PBKDF: 基于密码的密钥派生函数, 实现标准*RFC 8018, PKCS #5 Password-Based Crypography Specification*;
  - `PBKDF1<DigestX>`;
  - `PBKDF2<PRF>`;
- Scrypt: 基于密码的密钥派生函数(使用内存作为成本函数, 抗GPU, ASIC), 实现标准*RFC 7914*;
  - `Scrypt`;
- Argon2: 基于密码的密钥派生函数(使用内存作为成本函数, 抗GPU, ASIC), 实现标准*RFC 9106*;
  - `Argon2`;

== group

- 曲线:
  - short weierstrass曲线: P224, P256, P384, P521. 实现标准*SP 800-186*;

= utils

辅助工具crate

= my

*my*命令:
- `my fs`: 文件管理命令, 当前支持文件遍历, 类似`ls, tree`命令;
- `my tokei`: 统计代码, 需要安装tokei, 这里主要是统计之后会修改配置文件代码仓库记录;
- `my git`: git仓库管理, 仓库信息会记录在配置文件中`~/.config/my`;
  - `my git clone`: 克隆多个git厂库到指定的目录;
  - `my git copy/my git mv/my git rm`: 拷贝指定的仓库到指定目录;
  - `my git open`: 打开仓库记录信息;
  - `my git reduce`: 移除重复的记录信息;
  - `my git temp`: 查找有编译缓存文件的仓库;
  - `my git search`: 搜索指定正则的仓库;
  - `my git --update`: 更新指定的git仓库;
- `my enc`: 编码转换, 支持hex, bin, byte, base16, base32, base64, base58;
- `my h`: 哈希算法, 支持crypto_hash中的hash算法;
- `my c`: 加密算法, 支持cipher中的加密算法;
- `my s`: 签名算法, 支持cipher中的签名算法;
- `my k`: 密钥生成;
- `my sky`: 自定义的文件加密;
- `my mac`: 消息认证码;
- `my p`: 公钥加密;
- `my g`: 群相关命令;