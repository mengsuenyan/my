impl_fips202_hash!(
    SHA224,
    SHA3<144, 28>,
    doc = r"`SHA3-224(M) = KECCAK[448] (M || 01, 224)`"
);

#[cfg(test)]
mod tests {
    use crate::sha3::sha224::SHA224;
    use crate::Digest;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn sha3_224() {
        let cases = [
            ("6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7", ""),
            ("ebbe41003af4309fcbfe87f9139d59eb7a199f80bcdc78a6d5adfa6d", "11001000"),
            ("9376816ABA503F72F96CE7EB65AC095DEEE3BE4BF9BBC2A1CB7E11E0", "1100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101110001011100010111000101"),
        ].into_iter().map(|(digest, msg)| {
            let digest = BigUint::from_str_radix(digest, 16).unwrap().to_bytes_be();
            let (mut v, mut n) = (vec![], 0);
            for (i,&c) in msg.as_bytes().iter().rev().enumerate() {
                if i & 7 == 0 {
                    n = 0;
                }
                n <<= 1;
                n |= c - b'0';

                if i & 7 == 7 || i == msg.len() - 1 {
                    v.push(n);
                }
            }

            (digest, v)
        }).collect::<Vec<_>>();

        for (i, (tgt, msg)) in cases.into_iter().enumerate() {
            assert_eq!(
                tgt,
                SHA224::digest(msg.as_slice()).to_vec(),
                "case {i} failed"
            );
        }

        let cases = [
            "300d01f3a910045fefa16d6a149f38167b2503dbc37c1b24fd6f751e",
            "f3ff4f073ed24d62051c8d7bb73418b95db2f6ff9e4441af466f6d98",
            "b6f194539618d1e5eec08a56b8c7d09b8198fe1faa3f16e9703b91bd",
            "51bbf7daffa13cd37d2517dd38b1be95b200053bd4e36492b5566bda",
            "4a63debd3538267188df39677b980ddf64ff563264554210b43524ea",
            "970a4c0b7081bd6a245822c7e804d704db34d32acc7b771208a8c24a",
            "aa98ecf6824dad085b259424c29f535bc339c94bace0a7a031ec40e6",
            "2531506e5f2f02bd42cbbd39b3f8a181e120eb662b5c85471fa913b3",
            "2299019d2c50f7525fc39a05256f802de6e9d05328c903d298b03d9d",
            "a73d044ff856fe8cc41281c6623ec693c4ab7864c857218e09f9f876",
        ]
        .into_iter()
        .map(|x| BigUint::from_str_radix(x, 16).unwrap().to_bytes_be());

        for (i, tgt) in cases.into_iter().enumerate() {
            let x = format!("{}", i + 1);
            assert_eq!(
                tgt,
                SHA224::digest(x.as_bytes()).to_vec(),
                "case {i} failed"
            );
        }

        let cases = [
            ("7cac717bb740d734889b1bc444115d405574634a4476c6b5e9a6b0af", "This is the top level of the kernel's documentation tree. Kernel documentation, like the kernel itself, is very much a work in progress; that is especially true as we work to integrate our many scattered documents into a coherent whole. Please note that improvements to the documentation are welcome; join the linux-doc list at vger.kernel.org if you want to help out."),
        ].into_iter().map(|(x,y)| (BigUint::from_str_radix(x, 16).unwrap().to_bytes_be(), y)).collect::<Vec<_>>();

        for (i, (tgt, msg)) in cases.into_iter().enumerate() {
            assert_eq!(
                tgt,
                SHA224::digest(msg.as_bytes()).to_vec(),
                "case {i} failed"
            )
        }
    }
}
