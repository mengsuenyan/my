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

        let cases = [
            (
                "tIwTEM2Z0X",
                "2916a61c10ae08ec4fb61d334facb24fb19de83760819b8c1d92f1e0a1b07ab6",
            ),
            (
                "fRsuAQE0aFG",
                "4b27f3c3671f42424825a9cb0acd037bc5fdddee1c3d9d39104f3a11b90cb9a9",
            ),
            (
                "DwGQPt8RsXVo",
                "d431beae337c2b20ecc79df264300b96a20618a4699f86670f311451b8b3d1d5",
            ),
            (
                "2GPCVgNvHef7Z",
                "7b7284ffaa19b108fb9d0921e492f24fd408d389886d16519504ea411367577e",
            ),
            (
                "yTbFhTm4Df6GyQ",
                "d425f6c522622fe155c533b5fe4b5184b618b2cbcb09f7a7a4cd1e020f69e477",
            ),
            (
                "fJZC9WWbVhM7Ia5",
                "5153c21e5c944abb4a70d13e817e23294124fda05e091653ea893231be622c8c",
            ),
            (
                "prlhHCWsZj4sg9iX",
                "e104ee37332b7ffa9c683f044b66e0e6031e2e2f1f929107821e9060169b03ac",
            ),
            (
                "jfFDD27wLpXERYUsn",
                "0ea5b34e3f55e46d908f6cb903e446327618043c945acc92478de1c8717ded00",
            ),
            (
                "wKKenUIoUXZ2124cDm",
                "8e9c0b139644679c1e80f85b831e93d7b2cbd9504b17d7b8c88bd35148116037",
            ),
            (
                "iPZGwN7ecykbn3y73PF",
                "deec146ab330bd5fc935e352099507030fe839a67e4f0857fa5c4b537959205a",
            ),
            (
                "e7ukofnCFQNwjqsaZ1Zg",
                "62b3aad04704abd707146ae38e2631ba47bd7ff10335efe9f1de012c2a137134",
            ),
        ]
        .into_iter()
        .map(|(msg, h)| (msg, BigUint::from_str_radix(h, 16).unwrap().to_bytes_be()))
        .collect::<Vec<_>>();

        for (i, (msg, tgt)) in cases.into_iter().enumerate() {
            assert_eq!(
                tgt,
                SHA256::digest(msg.as_bytes()).to_vec(),
                "case {i} sha3-256sum failed"
            );
        }
    }
}
