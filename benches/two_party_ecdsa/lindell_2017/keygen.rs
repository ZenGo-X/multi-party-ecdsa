#[macro_use]
extern crate criterion;
extern crate cryptography_utils;
extern crate multi_party_ecdsa;

mod bench {
    use criterion::Criterion;
    use cryptography_utils::arithmetic::traits::Samplable;
    use cryptography_utils::elliptic::curves::traits::*;
    use cryptography_utils::BigInt;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

    pub fn bench_full_keygen_party_one_two(c: &mut Criterion) {
        c.bench_function("keygen", move |b| {
            b.iter(|| {
                let party_one_first_message =
                    party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
                        ECScalar::from(&BigInt::sample(253)),
                    );
                let party_two_first_message =
                    party_two::KeyGenFirstMsg::create_with_fixed_secret_share(ECScalar::from(
                        &BigInt::from(10),
                    ));
                let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
                    &party_one_first_message,
                    &party_two_first_message.d_log_proof,
                )
                .expect("failed to verify and decommit");

                let _party_two_second_message =
                    party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                        &party_one_first_message.pk_commitment,
                        &party_one_first_message.zk_pok_commitment,
                        &party_one_second_message.zk_pok_blind_factor,
                        &party_one_second_message.public_share,
                        &party_one_second_message.pk_commitment_blind_factor,
                        &party_one_second_message.d_log_proof,
                    )
                    .expect("failed to verify commitments and DLog proof");

                // init paillier keypair:
                let paillier_key_pair =
                    party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(
                        &party_one_first_message,
                    );

                let party_two_paillier = party_two::PaillierPublic {
                    ek: paillier_key_pair.ek.clone(),
                    encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
                };

                let correct_key_proof =
                    party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
                party_two::PaillierPublic::verify_ni_proof_correct_key(
                    correct_key_proof,
                    &party_two_paillier.ek,
                )
                .expect("bad paillier key");
                // zk proof of correct paillier key

                // zk range proof
                let (encrypted_pairs, challenge, proof) =
                    party_one::PaillierKeyPair::generate_range_proof(
                        &paillier_key_pair,
                        &party_one_first_message,
                    );
                let _result = party_two::PaillierPublic::verify_range_proof(
                    &party_two_paillier,
                    &challenge,
                    &encrypted_pairs,
                    &proof,
                )
                .expect("range proof error");

                // pdl proof minus range proof
                let pdl_chal =
                    party_two_paillier.pdl_challenge(&party_one_first_message.public_share);

                let pdl_prover = paillier_key_pair.pdl_first_stage(&pdl_chal.c_tag);

                let pdl_decom_party2 = party_two::PaillierPublic::pdl_decommit_c_tag_tag(&pdl_chal);

                let pdl_decom_party1 = party_one::PaillierKeyPair::pdl_second_stage(
                    &pdl_prover,
                    &pdl_chal.c_tag_tag,
                    &party_one_first_message,
                    &pdl_decom_party2.a,
                    &pdl_decom_party2.b,
                    &pdl_decom_party2.blindness,
                )
                .expect("pdl error party2");

                party_two::PaillierPublic::verify_pdl(
                    &pdl_chal,
                    &pdl_decom_party1.blindness,
                    &pdl_decom_party1.q_hat,
                    &pdl_prover.c_hat,
                )
                .expect("pdl error party1")
            })
        });
    }

    criterion_group!{
    name = keygen;
    config = Criterion::default().sample_size(10);
    targets =self::bench_full_keygen_party_one_two}
}

criterion_main!(bench::keygen);
