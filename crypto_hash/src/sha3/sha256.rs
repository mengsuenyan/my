impl_fips202_hash!(
    SHA256,
    SHA3<136, 32>,
    doc = r"`SHA3-256(M) = KECCAK[512] (M || 01, 256)`"
);

#[cfg(test)]
mod tests {
    use crate::sha3::sha256::SHA256;
    use crate::Digest;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn sha3_256() {
        let cases = [
            "67b176705b46206614219f47a05aee7ae6a3edbe850bbbe214c536b989aea4d2",
            "b1b1bd1ed240b1496c81ccf19ceccf2af6fd24fac10ae42023628abbe2687310",
            "1bf0b26eb2090599dd68cbb42c86a674cb07ab7adc103ad3ccdf521bb79056b9",
            "b410677b84ed73fac43fcf1abd933151dd417d932a0ef9b0260ecf8b7b72ecb9",
            "86bc56fc56af4c3cde021282f6b727ee9f90dd636e0b0c712a85d416c75e652d",
            "0c67354981e9068905680b57898ad4f04b993c63eb66aa3f19cdfdc71d88077e",
            "8f9b51ce624f01b0a40c9f68ba8bb0a2c06aa7f95d1ed27d6b1b5e1e99ee5e4d",
            "d14a329a1924592faf2d4ba6dc727d59af6afae983a0c208bf980237b63a5a6a",
            "7609430974b087595488c154bf5c079887ead0e8efd4055cd136fda96a5ccbf8",
            "dd121e36961a04627eacff629765dd3528471ed745c1e32222db4a8a5f3421c4",
        ]
        .into_iter()
        .map(|x| BigUint::from_str_radix(x, 16).unwrap().to_bytes_be())
        .collect::<Vec<_>>();

        for (i, tgt) in cases.into_iter().enumerate() {
            let msg = format!("{}", i + 1);
            assert_eq!(
                tgt,
                SHA256::digest(msg.as_bytes()).to_vec(),
                "case {i} failed"
            );
        }

        assert_eq!(
            BigUint::from_str_radix(
                "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A",
                16
            )
            .unwrap()
            .to_bytes_be(),
            SHA256::digest(&[]).to_vec(),
            r#"case "" failed"#,
        );

        let cases = [
            ("69b56c651934898fa75ff9994b1c52925f57b887b3ea0e41791d53741d4a8ce3", "This is the top level of the kernel's documentation tree. Kernel documentation, like the kernel itself, is very much a work in progress; that is especially true as we work to integrate our many scattered documents into a coherent whole. Please note that improvements to the documentation are welcome; join the linux-doc list at vger.kernel.org if you want to help out."),
        ].into_iter().map(|(x,y)| (BigUint::from_str_radix(x, 16).unwrap().to_bytes_be(), y)).collect::<Vec<_>>();

        for (i, (tgt, msg)) in cases.into_iter().enumerate() {
            assert_eq!(
                tgt,
                SHA256::digest(msg.as_bytes()).to_vec(),
                "case {i} failed"
            )
        }
    }
}
