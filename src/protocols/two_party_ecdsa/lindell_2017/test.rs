// For integration tests, please add your tests in /tests instead

#[cfg(test)]
mod tests {

    use cryptography_utils::arithmetic::traits::Samplable;
    use cryptography_utils::elliptic::curves::traits::*;
    use cryptography_utils::BigInt;
    use protocols::two_party_ecdsa::lindell_2017::*;

    #[test]
    fn test_d_log_proof_party_two_party_one() {
        let party_one_first_message = party_one::KeyGenFirstMsg::create_commitments();
        let party_two_first_message = party_two::KeyGenFirstMsg::create();
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
    }

    #[test]

    fn test_full_key_gen() {
        let party_one_first_message =
            party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(ECScalar::from(
                &BigInt::sample(253),
            ));
        let party_two_first_message = party_two::KeyGenFirstMsg::create_with_fixed_secret_share(
            ECScalar::from(&BigInt::from(10)),
        );
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
        let paillier_key_pair = party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(
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
        let (encrypted_pairs, challenge, proof) = party_one::PaillierKeyPair::generate_range_proof(
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
        let pdl_chal = party_two_paillier.pdl_challenge(&party_one_first_message.public_share);

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
    }

    #[test]
    fn test_two_party_sign() {
        // assume party1 and party2 engaged with KeyGen in the past resulting in
        // party1 owning private share and paillier key-pair
        // party2 owning private share and paillier encryption of party1 share
        let party_one_private_share_gen = party_one::KeyGenFirstMsg::create_commitments();
        let party_two_private_share_gen = party_two::KeyGenFirstMsg::create();

        let keypair = party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(
            &party_one_private_share_gen,
        );

        // creating the ephemeral private shares:

        let eph_party_two_first_message = party_two::EphKeyGenFirstMsg::create_commitments();
        let eph_party_one_first_message = party_one::EphKeyGenFirstMsg::create();
        let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
            &eph_party_two_first_message,
            &eph_party_one_first_message.d_log_proof,
        )
        .expect("party1 DLog proof failed");

        let _eph_party_one_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &eph_party_two_first_message.pk_commitment,
                &eph_party_two_first_message.zk_pok_commitment,
                &eph_party_two_second_message.zk_pok_blind_factor,
                &eph_party_two_second_message.public_share,
                &eph_party_two_second_message.pk_commitment_blind_factor,
                &eph_party_two_second_message.d_log_proof,
            )
            .expect("failed to verify commitments and DLog proof");
        let party2_private =
            party_two::Party2Private::set_private_key(&party_two_private_share_gen);
        let message = BigInt::from(1234);
        let partial_sig = party_two::PartialSig::compute(
            &keypair.ek,
            &keypair.encrypted_share,
            &party2_private,
            &eph_party_two_first_message,
            &eph_party_one_first_message.public_share,
            &message,
        );

        let party1_private =
            party_one::Party1Private::set_private_key(&party_one_private_share_gen, &keypair);

        let signature = party_one::Signature::compute(
            &party1_private,
            &partial_sig.c3,
            &eph_party_one_first_message,
            &eph_party_two_first_message.public_share,
        );

        let pubkey = party_one::compute_pubkey(
            &party_one_private_share_gen,
            &party_two_private_share_gen.public_share,
        );
        party_one::verify(&signature, &pubkey, &message).expect("Invalid signature")
    }
}
