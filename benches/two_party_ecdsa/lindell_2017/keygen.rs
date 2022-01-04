use criterion::criterion_main;

mod bench {
    use criterion::{criterion_group, Criterion};
    use curv::arithmetic::traits::Samplable;
    use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};
    use curv::BigInt;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

    pub fn bench_full_keygen_party_one_two(c: &mut Criterion) {
        c.bench_function("keygen", move |b| {
            b.iter(|| {
                let (party_one_first_message, comm_witness, ec_key_pair_party1) =
                    party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
                        Scalar::<Secp256k1>::from(&BigInt::sample(253)),
                    );
                let (party_two_first_message, _ec_key_pair_party2) =
                    party_two::KeyGenFirstMsg::create_with_fixed_secret_share(
                        Scalar::<Secp256k1>::from(&BigInt::from(10)),
                    );
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

                // init paillier keypair:
                let paillier_key_pair =
                    party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(
                        &ec_key_pair_party1,
                    );

                let party_one_private = party_one::Party1Private::set_private_key(
                    &ec_key_pair_party1,
                    &paillier_key_pair,
                );

                let party_two_paillier = party_two::PaillierPublic {
                    ek: paillier_key_pair.ek.clone(),
                    encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
                };

                // zk proof of correct paillier key
                let correct_key_proof =
                    party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
                party_two::PaillierPublic::verify_ni_proof_correct_key(
                    correct_key_proof,
                    &party_two_paillier.ek,
                )
                .expect("bad paillier key");

                //zk_pdl

                let (pdl_statement, pdl_proof, composite_dlog_proof) =
                    party_one::PaillierKeyPair::pdl_proof(&party_one_private, &paillier_key_pair);
                party_two::PaillierPublic::pdl_verify(
                    &composite_dlog_proof,
                    &pdl_statement,
                    &pdl_proof,
                    &party_two_paillier,
                    &party_one_second_message.comm_witness.public_share,
                )
                .expect("PDL error");
            })
        });
    }

    criterion_group! {
    name = keygen;
    config = Criterion::default().sample_size(10);
    targets =self::bench_full_keygen_party_one_two}
}

criterion_main!(bench::keygen);
