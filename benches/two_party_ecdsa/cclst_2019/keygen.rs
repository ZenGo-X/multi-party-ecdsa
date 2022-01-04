use criterion::criterion_main;

mod bench {
    use criterion::{criterion_group, Criterion};
    use curv::arithmetic::traits::Samplable;
    use curv::elliptic::curves::traits::*;
    use curv::BigInt;
    use multi_party_ecdsa::protocols::two_party_ecdsa::cclst_2019::{party_one, party_two};

    pub fn bench_full_keygen_party_one_two(c: &mut Criterion) {
        c.bench_function("keygen", move |b| {
            b.iter(|| {

                let (party_one_first_message, comm_witness, ec_key_pair_party1) =
                    party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
                        Scalar::<Secp256k1>::random(),
                    );
                let (party_two_first_message, _ec_key_pair_party2) =
                    party_two::KeyGenFirstMsg::create_with_fixed_secret_share(Scalar::<Secp256k1>::from(&BigInt::from(
                        10,
                    )));
                let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
                    comm_witness,
                    &party_two_first_message.d_log_proof,
                )
                    .expect("failed to verify and decommit");

                let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                    &party_one_first_message,
                    &party_one_second_message,
                )
                    .expect("failed to verify commitments and DLog proof");

                // init HSMCL keypair:
                let seed: BigInt = str::parse(
                    "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
                ).unwrap();
                let (hsmcl, hsmcl_public) = party_one::HSMCL::generate_keypair_and_encrypted_share_and_proof(
                    &ec_key_pair_party1,
                    &seed,
                );

                //P1 sends P2 hsmcl_public
                let _party_one_private = party_one::Party1Private::set_private_key(&ec_key_pair_party1, &hsmcl);

                let _party_two_hsmcl_pub = party_two::Party2Public::verify_setup_and_zkcldl_proof(
                    &hsmcl_public,
                    &seed,
                    &party_one_second_message.comm_witness.public_share,
                )
                    .expect("proof error");


            })
        });
    }

    criterion_group! {
    name = keygen;
    config = Criterion::default().sample_size(10);
    targets =self::bench_full_keygen_party_one_two}
}

criterion_main!(bench::keygen);
