extern crate cryptography_utils;
extern crate multi_party_ecdsa;

use cryptography_utils::BigInt;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

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

    let party_one_first_message = party_one::KeyGenFirstMsg::create_commitments();
    let party_two_first_message = party_two::KeyGenFirstMsg::create();
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        &party_one_first_message,
        &party_two_first_message.d_log_proof,
    ).expect("party1 DLog proof failed");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message.pk_commitment,
        &party_one_first_message.zk_pok_commitment,
        &party_one_second_message.zk_pok_blind_factor,
        &party_one_second_message.public_share,
        &party_one_second_message.pk_commitment_blind_factor,
        &party_one_second_message.d_log_proof,
    ).expect("failed to verify commitments and DLog proof");
    let party2_private = party_two::Party2Private::set_private_key(&party_two_private_share_gen);
    let message = BigInt::from(1234);
    let partial_sig = party_two::PartialSig::compute(
        &keypair.ek,
        &keypair.encrypted_share,
        &party2_private,
        &party_two_first_message,
        &party_one_second_message.public_share,
        &message,
    );

    let party1_private =
        party_one::Party1Private::set_private_key(&party_one_private_share_gen, &keypair);

    let signature = party_one::Signature::compute(
        &party1_private,
        &partial_sig.c3,
        &party_one_first_message,
        &party_two_first_message.public_share,
    );

    let pubkey = party_one::compute_pubkey(
        &party_one_private_share_gen,
        &party_two_private_share_gen.public_share,
    );
    party_one::verify(&signature, &pubkey, &message).expect("Invalid signature")
}
