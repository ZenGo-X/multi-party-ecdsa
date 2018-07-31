extern crate cryptography_utils;
extern crate multi_party_ecdsa;

use cryptography_utils::EC;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

#[test]
fn test_two_party_keygen() {
    let ec_context = EC::new();

    // secret share generation
    let party_one_first_message = PartyOneKeyGenFirstMsg::create_commitments(&ec_context);
    let party_two_first_message = PartyTwoKeyGenFirstMsg::create(&ec_context);
    let party_one_second_message = PartyOneKeyGenSecondMsg::verify_and_decommit(
        &ec_context,
        &party_one_first_message,
        &party_two_first_message.d_log_proof,
    ).expect("failed to verify and decommit");

    let _party_two_second_message = PartyTwoKeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &ec_context,
        &party_one_first_message,
        &party_one_second_message,
    ).expect("failed to verify commitments and DLog proof");

    // init paillier keypair:
    let paillier_key_pair =
        PartyOnePaillierKeyPair::generate_keypair_and_encrypted_share(&party_one_first_message);

    let party_two_paillier = PartyTwoPaillierPublic {
        ek: paillier_key_pair.ek.clone(),
        encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
    };

    // zk proof of correct paillier key
    let (challenge, verification_aid) =
        PartyTwoPaillierPublic::generate_correct_key_challenge(&party_two_paillier);
    let proof_result =
        PartyOnePaillierKeyPair::generate_proof_correct_key(&paillier_key_pair, &challenge);

    let valid_proof = proof_result.expect("Incorrect party #1 correct key proof");
    PartyTwoPaillierPublic::verify_correct_key(&valid_proof, &verification_aid)
        .expect("Incorrect party #2 correct key verification");

    // zk range proof
    let (encrypted_pairs, challenge, proof) =
        PartyOnePaillierKeyPair::generate_range_proof(&paillier_key_pair, &party_one_first_message);

    assert!(PartyTwoPaillierPublic::verify_range_proof(
        &party_two_paillier,
        &challenge,
        &encrypted_pairs,
        &proof,
    ));
}
