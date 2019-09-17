#[macro_use]
extern crate criterion;
extern crate curv;
extern crate multi_party_ecdsa;

mod bench {
    use criterion::Criterion;
    use curv::arithmetic::traits::Samplable;
    use curv::elliptic::curves::traits::*;
    use curv::BigInt;
    use multi_party_ecdsa::protocols::two_party_ecdsa::cclst_2019::*;

    pub fn bench_full_keygen_party_one_two(c: &mut Criterion) {
        c.bench_function("keygen", move |b| {
            b.iter(|| {
                let (party_one_first_message, comm_witness, ec_key_pair_party1) =
                    party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
                        ECScalar::from(&BigInt::sample(253)),
                    );
                let (party_two_first_message, _ec_key_pair_party2) =
                    party_two::KeyGenFirstMsg::create_with_fixed_secret_share(ECScalar::from(
                        &BigInt::from(10),
                    ));
                let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
                    comm_witness,
                    &party_two_first_message.d_log_proof,
                )
                .expect("failed to verify and decommit");

                let _party_two_second_message =
                    party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                        &party_one_first_message,
                        &party_one_second_message,
                    )
                    .expect("failed to verify commitments and DLog proof");

                // init HSMCL keypair:
                let hsmcl_key_pair = party_one::HSMCLKeyPair::generate_keypair_and_encrypted_share(
                    &ec_key_pair_party1,
                );

                let party_one_private =
                    party_one::Party1Private::set_private_key(&ec_key_pair_party1, &hsmcl_key_pair);

                let cldl_proof = party_one::HSMCLKeyPair::generate_zkcldl_proof(
                    &hsmcl_key_pair,
                    &party_one_private,
                );
                let _party_two_hsmcl_pub =
                    party_two::HSMCLPublic::verify_zkcldl_proof(cldl_proof).expect("proof error");
            })
        });
    }

    criterion_group! {
    name = keygen;
    config = Criterion::default().sample_size(10);
    targets =self::bench_full_keygen_party_one_two}
}

criterion_main!(bench::keygen);
