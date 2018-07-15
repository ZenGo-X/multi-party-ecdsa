#[cfg(test)]
mod tests {
    use cryptography_utils::EC;

    use protocols::two_party_ecdsa::lindell_2017_keygen::*;

    #[test]
    fn test_d_log_proof_party_two_party_one() {
        let ec_context = EC::new();
        let party_one_first_message = party_one::FirstMsg::create_commitments(&ec_context);
        let party_two_first_message = party_two::FirstMsg::create(&ec_context);
        let party_one_second_message = party_one::SecondMsg::verify_and_decommit(&ec_context, &party_one_first_message,&party_two_first_message);
        assert!(party_one_second_message.d_log_proof_result.is_ok());
        let party_two_second_message  = party_two::SecondMsg::verify_commitments_and_dlog_proof(&ec_context, &party_one_first_message, &party_one_second_message);
        assert!(party_two_second_message.d_log_proof_result.is_ok());
    }

}