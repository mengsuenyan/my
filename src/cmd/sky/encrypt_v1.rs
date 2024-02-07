use super::SkyEncrypt;
use super::SkyEncryptHeader;
use crypto_hash::DigestX;
use encode::{base::Base64, Decode, Encode};
use std::io::Write;

impl SkyEncrypt {
    pub fn update_iv_from_header_v1(
        &mut self,
        header: &SkyEncryptHeader,
    ) -> anyhow::Result<Vec<u8>> {
        if let Some(update_iv) = self.update_iv.as_ref() {
            self.iv_cshake.reset_x();
            self.iv_cshake.write_all(self.key.as_slice())?;
            self.iv_cshake.write_all(&header.file_name)?;
            self.iv_cshake
                .write_all(header.file_len.to_be_bytes().as_slice())?;
            let iv = self.iv_cshake.finish_x();
            update_iv(iv.clone())?;
            Ok(iv)
        } else {
            anyhow::bail!("no update iv function")
        }
    }

    fn update_iv_v1(&mut self, iv: Vec<u8>) -> anyhow::Result<()> {
        if let Some(update_iv) = self.update_iv.as_ref() {
            update_iv(iv)?;
        }

        Ok(())
    }

    pub fn encrypt_v1(&mut self, in_data: &[u8], filename: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut header = SkyEncryptHeader::from(&*self);
        header.set_data_size(in_data.len());
        header.set_file_name(filename);

        let iv = self.update_iv_from_header_v1(&header)?;

        let (h, mut encrypted_h) = (self.digest.digest(in_data), Vec::with_capacity(1024));
        let _ = self
            .cipher
            .stream_encrypt_x(h.as_slice(), &mut encrypted_h)?;
        let _ = self.cipher.stream_encrypt_finish_x(&mut encrypted_h);
        header.set_digest(encrypted_h);

        let mut data = header.into_vec();

        self.update_iv_v1(iv)?;
        let _x = self.cipher.stream_encrypt_x(in_data, &mut data)?;
        let _x = self.cipher.stream_encrypt_finish_x(&mut data)?;

        if self.is_base64 {
            let mut b64 = Base64::new(true);
            let mut b64_data = Vec::with_capacity(data.len() + (data.len() >> 1));
            b64.encode(&mut data.as_slice(), &mut b64_data)?;

            Ok(b64_data)
        } else {
            Ok(data)
        }
    }

    pub fn decrypt_digest_v1(&mut self, header: &SkyEncryptHeader) -> anyhow::Result<Vec<u8>> {
        let _ = self.update_iv_from_header_v1(header)?;
        let mut h = Vec::with_capacity(header.digest.len());
        let _ = self.cipher.stream_decrypt_x(&header.digest, &mut h)?;
        let _ = self.cipher.stream_decrypt_finish_x(&mut h)?;
        Ok(h)
    }

    pub fn decrypt_v1(&mut self, mut in_data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(0);
        let in_data = if self.is_base64 {
            buf.reserve(in_data.len());
            let mut b64 = Base64::new(true);
            b64.decode(&mut in_data, &mut buf)?;
            buf.as_slice()
        } else {
            in_data
        };

        let header = SkyEncryptHeader::try_from(in_data)?;
        let cipher_data = &in_data[header.file_offset()..];

        let iv = self.update_iv_from_header_v1(&header)?;

        let mut original_h = Vec::with_capacity(1024);
        let _ = self
            .cipher
            .stream_decrypt_x(&header.digest, &mut original_h)?;
        let _ = self.cipher.stream_decrypt_finish_x(&mut original_h);

        self.update_iv_v1(iv)?;
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
            h == original_h,
            "the decrypt data hash not equal to original file hash"
        );

        Ok(data)
    }
}
