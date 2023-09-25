impl_fips202_hash!(
    SHA384,
    SHA3<104, 48>,
    doc = r"`SHA3-384(M) = KECCAK[768] (M || 01, 384)`"
);

#[cfg(test)]
mod tests {
    use crate::sha3::sha384::SHA384;
    use crate::Digest;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn sha3_384() {
        let cases = [
                "f39de487a8aed2d19069ed7a7bcfc274e9f026bba97c8f059be6a2e5eed051d7ee437b93d80aa6163bf8039543b612dd",
                "39773563a8fc5c19ba80f0dc0f57bf49ba0e804abe8e68a1ed067252c30ef499d54ab4eb4e8f4cfa2cfac6c83798997e",
                "5f9714f2c47c4ee6af02e96db42b64a3750f5ec5f3541d1a1a6fd20d3632395c55439e208557e782f22a9714885b6e0c",
                "d87826dc897a66ee657458dbbe788e473e809b47c93bb37902b74b53999ae64a0ecdc8f76b28b608c2bf66f836d1b8d9",
                "d17e08f9fd1ec955b2384bba9312e525edad397e244071a0dd499c3403719434c5c21d833e7ecd46ed47f14d2bdbcfa3",
                "7cca6b41713794de552e96349b5f5bf35fa9f12806bfce76a5aa3cdd450e0a98495be64b2023f3188e80cbe27c802d1b",
                "4bf873ccb328cdc95a26473588df6c107706c166e240294fc5c70c2b220adc9314e166b0a77344825a34a835cb422ebb",
                "854ed8ecc48ed40a6bbf2fc0de3cfbd1811937e23340b245d2d618dc3d5349dbb0fea84e54184557247df6f456731040",
                "4894ec28d9d6494918765447867b8fbe65f7a6ec5a30f5aa3ce168c766fb8f9c63cb02602c730e8b259381942ac1f49b",
                "48cbe0a67ec78f9e5313b88de9cff586b270e399b52d64b5226c87fc4cd31e986a3f21b63e9135404ceadfc1199e993e",
        ].into_iter().map(|x| {
            BigUint::from_str_radix(x, 16).unwrap().to_bytes_be()
        }).collect::<Vec<_>>();

        for (i, tgt) in cases.into_iter().enumerate() {
            let msg = format!("{}", i + 1);
            assert_eq!(
                tgt,
                SHA384::digest(msg.as_bytes()).to_vec(),
                "case {i} failed"
            );
        }

        assert_eq!(
            BigUint::from_str_radix("0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004", 16).unwrap().to_bytes_be(),
            SHA384::digest(&[]).to_vec(),
            r#"case "" failed"#,
        );

        let cases = [
            ("569a2f90fdf7601ba36c48e0aa136fbfd6aadcf34c02cf10e25601ad765648550b4a40f287c99964241cc0d471203ba9", "This is the top level of the kernel's documentation tree. Kernel documentation, like the kernel itself, is very much a work in progress; that is especially true as we work to integrate our many scattered documents into a coherent whole. Please note that improvements to the documentation are welcome; join the linux-doc list at vger.kernel.org if you want to help out."),
        ].into_iter().map(|(x,y)| (BigUint::from_str_radix(x, 16).unwrap().to_bytes_be(), y)).collect::<Vec<_>>();

        for (i, (tgt, msg)) in cases.into_iter().enumerate() {
            assert_eq!(
                tgt,
                SHA384::digest(msg.as_bytes()).to_vec(),
                "case {i} failed"
            )
        }
    }
}
