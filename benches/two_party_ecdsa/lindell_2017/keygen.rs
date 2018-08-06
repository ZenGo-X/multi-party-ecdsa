#[macro_use]
extern crate bencher;
extern crate cryptography_utils;
extern crate multi_party_ecdsa;

mod bench {
    use bencher::*;
    use cryptography_utils::EC;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

    pub fn bench_full_keygen_party_one_two(b: &mut Bencher) {
        b.iter(|| {
            let ec_context = EC::new();
            let party_one_first_message =
                party_one::KeyGenFirstMsg::create_commitments(&ec_context);
            let party_two_first_message = party_two::KeyGenFirstMsg::create(&ec_context);
            let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
                &ec_context,
                &party_one_first_message,
                &party_two_first_message.d_log_proof.val,
            ).expect("failed to verify and decommit");

            let _party_two_second_message =
                party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                    &ec_context,
                    &party_one_first_message.pk_commitment,
                    &party_one_first_message.zk_pok_commitment,
                    &party_one_second_message.zk_pok_blind_factor,
                    &party_one_second_message.public_share,
                    &party_one_second_message.pk_commitment_blind_factor,
                    &party_one_second_message.d_log_proof,
                ).expect("failed to verify commitments and DLog proof");

            // init paillier keypair:
            let paillier_key_pair =
                party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(
                    &party_one_first_message,
                );

            let party_two_paillier = party_two::PaillierPublic {
                ek: paillier_key_pair.ek.clone(),
                encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
            };

            // zk proof of correct paillier key
            let (challenge, verification_aid) =
                party_two::PaillierPublic::generate_correct_key_challenge(&party_two_paillier);
            let proof_result = party_one::PaillierKeyPair::generate_proof_correct_key(
                &paillier_key_pair,
                &challenge,
            );

            let _result = party_two::PaillierPublic::verify_correct_key(
                &proof_result.unwrap(),
                &verification_aid,
            );

            // zk range proof
            let (encrypted_pairs, challenge, proof) =
                party_one::PaillierKeyPair::generate_range_proof(
                    &paillier_key_pair,
                    &party_one_first_message,
                );
            party_two::PaillierPublic::verify_range_proof(
                &party_two_paillier,
                &challenge,
                &encrypted_pairs,
                &proof,
            );
        });
    }

    benchmark_group!(keygen, self::bench_full_keygen_party_one_two);
}

benchmark_main!(bench::keygen);
