// For integration tests, please add your tests in /tests instead

#[cfg(test)]
mod tests {
    use cryptography_utils::EC;
    use protocols::two_party_ecdsa::lindell_2017::*;

    #[test]
    fn test_d_log_proof_party_two_party_one() {
        let ec_context = EC::new();
        let party_one_first_message = party_one::KeyGenFirstMsg::create_commitments(&ec_context);
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
    }
}
