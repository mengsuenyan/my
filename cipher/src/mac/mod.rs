
/// marker for Message Authentication Code <br>
///
/// 以某个密钥生成指定长度的消息摘要, 用于验证消息的完整性和身份验证(拥有该密钥的身份者才能够生成该摘要)
pub trait MAC {}
