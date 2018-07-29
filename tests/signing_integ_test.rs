extern crate cryptography_utils;
extern crate multi_party_ecdsa;

use cryptography_utils::{BigInt, EC};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

#[test]
fn test_two_party_sign() {
    let ec_context = EC::new();
    // assume party1 and party2 engaged with KeyGen in the past resulting in
    // party1 owning private share and paillier key-pair
    // party2 owning private share and paillier encryption of party1 share
    let party_one_private_share_gen = party_one::KeyGenFirstMsg::create_commitments(&ec_context);
    let party_two_private_share_gen = party_two::KeyGenFirstMsg::create(&ec_context);

    let keypair = party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(
        &party_one_private_share_gen,
    );

    // creating the ephemeral private shares:

    let party_one_first_message = party_one::KeyGenFirstMsg::create_commitments(&ec_context);
    let party_two_first_message = party_two::KeyGenFirstMsg::create(&ec_context);
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        &ec_context,
        &party_one_first_message,
        &party_two_first_message.d_log_proof,
    );
    party_one_second_message
        .d_log_proof_result
        .expect("Party one DLog proved.");

    let party_two_proof_result = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &ec_context,
        &party_one_first_message,
        &party_one_second_message,
    );
    party_two_proof_result
        .d_log_proof_result
        .expect("Party two DLog proved.");

    let message = BigInt::from(1234);
    let partial_sig = party_two::PartialSig::compute(
        &ec_context,
        &keypair.ek,
        &keypair.encrypted_share,
        &party_two_private_share_gen,
        &party_two_first_message,
        &party_one_first_message,
        &message,
    );

    let signature = party_one::Signature::compute(
        &ec_context,
        &keypair,
        &partial_sig,
        &party_one_first_message,
        &party_two_first_message,
    );

    let pubkey = party_one::compute_pubkey(
        &ec_context,
        &party_one_private_share_gen,
        &party_two_private_share_gen,
    );
    party_one::verify(&ec_context, &signature, &pubkey, &message).expect("Correct signature")
}
