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
            &party_two_first_message.d_log_proof,
        );
        party_one_second_message
            .d_log_proof_result
            .expect("Party one DLog proved");

        let party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &ec_context,
                &party_one_first_message,
                &party_one_second_message,
            );
        party_two_second_message
            .d_log_proof_result
            .expect("Party two DLog proved");
    }
}
