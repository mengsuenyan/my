impl_fips202_hash!(
    SHA512,
    SHA3<72, 64>,
    doc = r"`SHA3-512(M) = KECCAK[1024] (M || 01, 512)`"
);

#[cfg(test)]
mod tests {
    use crate::sha3::sha512::SHA512;
    use crate::Digest;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn sha3_512() {
        let cases = [
                "ca2c70bc13298c5109ee0cb342d014906e6365249005fd4beee6f01aee44edb531231e98b50bf6810de6cf687882b09320fdd5f6375d1f2debd966fbf8d03efa",
                "564e1971233e098c26d412f2d4e652742355e616fed8ba88fc9750f869aac1c29cb944175c374a7b6769989aa7a4216198ee12f53bf7827850dfe28540587a97",
                "73fb266a903f956a9034d52c2d2793c37fddc32077898f5d871173da1d646fb80bbc21a0522390b75d3bcc88bd78960bdb73be323ad5fc5b3a16089992957d3a",
                "37f558134baa535903c6a88931c8122e334368bf951f2cada569b11774ef9795ef6d2ac961d13ee44a0c837db3817bb9db68ac3bdfb8b19a1308618484a9da8f",
                "c74bd95b8555275277d4e941c73985b4bcd923b36fcce75968ebb3c5a8d2b1ac411cfae4c2d473bff59a2b7b5ea220f0ac7bb8c880afb32f1b4881d59cc60d85",
                "503ad3364d41a2362f28136ee8a9615108277986f52c34ca170b664eb1c663f5e407e9a3084e90017e315b24ba9162021c477e29b3bb1f84a37eea841fe12b9a",
                "72ce921155976b88a4a4bf39a4127c4d9e272eccde35ee864963da855f32330c0f8075aafc3a3aadecf498ee7b5e2f9ee3529ea46d97ee0795bd548b41463771",
                "f30e8484fa863883156c517514c4e2a9096ec6009f40ebfb9f00666ec58e52e50e64f9074c9182a325a21cc99516b155560f8c48be28f11f2ee73f6945ff7563",
                "b55cf27ef01025e3c761a579a63d1c7c1e54e2d12f8f2928c90f5f5516b0d9c71f2fac9e7ccf28c5adf33c3f78d9548ebfed2dc46dea944aed336d1650721487",
                "0af1abec626b095704a5b03c13e47c3c18bcedb78566b6cadc4d5201cdb27691ce62fe60835587d41c8290616ad4ff1018b14dac6f83ff005922b25925fa4e6a",

        ].into_iter().map(|x| {
            BigUint::from_str_radix(x, 16).unwrap().to_bytes_be()
        }).collect::<Vec<_>>();

        for (i, tgt) in cases.into_iter().enumerate() {
            let msg = format!("{}", i + 1);
            assert_eq!(
                tgt,
                SHA512::digest(msg.as_bytes()).to_vec(),
                "case {i} failed"
            );
        }

        assert_eq!(
            BigUint::from_str_radix("A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26", 16).unwrap().to_bytes_be(),
            SHA512::digest(&[]).to_vec(),
            r#"case "" failed"#,
        );

        let cases = [
            ("c0ecb5e9d5665a52c7f93a52987a42bc63bc9d027f722d43eb08d6b11a3eadf6ac78ae53fb306b0ab25c55f6876d9f89bdf8903492368d4a07aa8828818f0701", "This is the top level of the kernel's documentation tree. Kernel documentation, like the kernel itself, is very much a work in progress; that is especially true as we work to integrate our many scattered documents into a coherent whole. Please note that improvements to the documentation are welcome; join the linux-doc list at vger.kernel.org if you want to help out."),
        ].into_iter().map(|(x,y)| (BigUint::from_str_radix(x, 16).unwrap().to_bytes_be(), y)).collect::<Vec<_>>();

        for (i, (tgt, msg)) in cases.into_iter().enumerate() {
            assert_eq!(
                tgt,
                SHA512::digest(msg.as_bytes()).to_vec(),
                "case {i} failed"
            )
        }
    }
}
