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
    let party_one_private_share_gen = PartyOneKeyGenFirstMsg::create_commitments(&ec_context);
    let party_two_private_share_gen = PartyTwoKeyGenFirstMsg::create(&ec_context);

    let keypair =
        PartyOnePaillierKeyPair::generate_keypair_and_encrypted_share(&party_one_private_share_gen);

    // creating the ephemeral private shares:

    let party_one_first_message = PartyOneKeyGenFirstMsg::create_commitments(&ec_context);
    let party_two_first_message = PartyTwoKeyGenFirstMsg::create(&ec_context);
    let party_one_second_message = PartyOneKeyGenSecondMsg::verify_and_decommit(
        &ec_context,
        &party_one_first_message,
        &party_two_first_message.d_log_proof,
    ).expect("party1 DLog proof failed");

    let _party_two_proof_result = PartyTwoKeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &ec_context,
        &party_one_first_message,
        &party_one_second_message,
    ).expect("party2 DLog proof failed");

    let message = BigInt::from(1234);
    let partial_sig = PartyTwoPartialSig::compute(
        &ec_context,
        &keypair.ek,
        &keypair.encrypted_share,
        &party_two_private_share_gen,
        &party_two_first_message,
        &party_one_first_message,
        &message,
    );

    let signature = PartyOneSignature::compute(
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
    party_one::verify(&ec_context, &signature, &pubkey, &message).expect("Invalid signature")
}
