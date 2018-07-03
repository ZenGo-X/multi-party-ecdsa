#[cfg(test)]
mod tests {
    use ::EC;
    use ::BigInteger as BigInt;

    use protocols::two_party_ecdsa::lindell_2017_keygen::*;

    #[test]
    fn test_first_interaction() {
        let ec_context = EC::new();

        let client_DLog_proof =
            party_two::FirstMsgCommitment::create(&ec_context);

        let second_msg_client_proof_verification =
            party_one::SecondMsgClientProofVerification::verify(&ec_context, &client_DLog_proof);


        /*let server_first_msg_commitments =
            party_one::FirstMsgCommitments::create(&ec_context);

        println!("server_first_msg_commitments: {:?}", server_first_msg_commitments);
        println!("client_first_msg_commitments: {:?}", client_DLog_proof);*/
    }
}