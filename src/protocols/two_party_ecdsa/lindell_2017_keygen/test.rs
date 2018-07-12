#[cfg(test)]
mod tests {
    use cryptography_utils::EC;

    use protocols::two_party_ecdsa::lindell_2017_keygen::*;

    #[test]
    fn test_d_log_proof_party_two_party_one() {
        let ec_context = EC::new();

        let party_two_d_log_proof =
            party_two::FirstMsgCommitment::create(&ec_context);

        let second_msg_party_two_proof_verification =
            party_one::SecondMsgClientProofVerification::verify(&ec_context, &party_two_d_log_proof);

        assert!(second_msg_party_two_proof_verification.d_log_proof_result.is_ok());
    }
}