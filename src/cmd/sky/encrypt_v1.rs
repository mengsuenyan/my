use super::SkyEncrypt;
use super::SkyEncryptHeader;
use crypto_hash::DigestX;
use encode::{base::Base64, Decode, Encode};
use std::io::Write;

impl SkyEncrypt {
    pub fn encrypt_v1(&mut self, in_data: &[u8], filename: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut header = SkyEncryptHeader::from(&*self);
        header.set_data_size(in_data.len());
        header.set_file_name(filename);

        self.digest.reset_x();
        self.digest.write_all(in_data)?;
        let h = self.digest.finish_x();
        header.set_digest(h);

        if let Some(update_iv) = self.update_iv.as_ref() {
            self.iv_cshake.reset_x();
            self.iv_cshake.write_all(self.key.as_slice())?;
            self.iv_cshake.write_all(filename)?;
            self.iv_cshake
                .write_all(header.file_len.to_be_bytes().as_slice())?;
            let iv = self.iv_cshake.finish_x();
            update_iv(iv)?;
        }

        let mut data = header.into_vec();

        let _x = self.cipher.stream_encrypt_x(in_data, &mut data)?;
        let _x = self.cipher.stream_encrypt_finish_x(&mut data)?;

        let mut b64 = Base64::new(true);
        let mut b64_data = Vec::with_capacity(data.len() + (data.len() >> 1));
        b64.encode(&mut data.as_slice(), &mut b64_data)?;

        Ok(b64_data)
    }

    pub fn decrypt_v1(&mut self, mut in_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut b64 = Base64::new(true);
        let mut buf = Vec::with_capacity(in_data.len());
        b64.decode(&mut in_data, &mut buf)?;
        let in_data = buf.as_slice();

        let header = SkyEncryptHeader::try_from(in_data)?;
        let cipher_data = &in_data[header.file_offset()..];

        if let Some(update_iv) = self.update_iv.as_ref() {
            self.iv_cshake.reset_x();
            self.iv_cshake.write_all(self.key.as_slice())?;
            self.iv_cshake.write_all(header.file_name.as_slice())?;
            self.iv_cshake
                .write_all(header.file_len.to_be_bytes().as_slice())?;
            let iv = self.iv_cshake.finish_x();
            update_iv(iv)?;
        }

        let mut data = Vec::with_capacity(1024);
        let _x = self.cipher.stream_decrypt_x(cipher_data, &mut data)?;
        let _x = self.cipher.stream_decrypt_finish_x(&mut data)?;

        anyhow::ensure!(
            data.len() == header.file_len as usize,
            "decrypt data len `{}` not equal to original file len `{}`",
            data.len(),
            header.file_len
        );

        self.digest.reset_x();
        self.digest.write_all(data.as_slice())?;
        let h = self.digest.finish_x();

        anyhow::ensure!(
            h == header.digest,
            "the decrypt data hash not equal to original file hash"
        );

        Ok(data)
    }
}
