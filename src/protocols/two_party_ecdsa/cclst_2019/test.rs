// For integration tests, please add your tests in /tests instead

use super::*;
use curv::arithmetic::Converter;
use curv::elliptic::curves::*;
use curv::BigInt;

#[test]
fn test_d_log_proof_party_two_party_one() {
    let (party_one_first_message, comm_witness, _ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (party_two_first_message, _ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        comm_witness,
        &party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message,
        &party_one_second_message,
    )
    .expect("failed to verify commitments and DLog proof");
}

#[test]
fn test_full_key_gen() {
    let (party_one_first_message, comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
            Scalar::<Secp256k1>::random(),
        );
    let (party_two_first_message, _ec_key_pair_party2) =
        party_two::KeyGenFirstMsg::create_with_fixed_secret_share(Scalar::<Secp256k1>::from(
            &BigInt::from(10),
        ));
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        comm_witness,
        &party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message,
        &party_one_second_message,
    )
    .expect("failed to verify commitments and DLog proof");

    // init HSMCL keypair:
    let seed: BigInt = BigInt::from_str_radix(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848",
        10,
    ).unwrap();
    let (hsmcl, hsmcl_public) = party_one::HSMCL::generate_keypair_and_encrypted_share_and_proof(
        &ec_key_pair_party1,
        &seed,
    );

    //P1 sends P2 hsmcl_public
    let _party_one_private = party_one::Party1Private::set_private_key(&ec_key_pair_party1, &hsmcl);

    let _party_two_hsmcl_pub = party_two::Party2Public::verify_setup_and_zkcldl_proof(
        &hsmcl_public,
        &seed,
        &party_one_second_message.comm_witness.public_share,
    )
    .expect("proof error");
}

#[test]
fn test_two_party_sign() {
    ////////// Simulate KeyGen /////////////////
    // assume party1 and party2 engaged with KeyGen in the past resulting in
    // party1 owning private share and HSMCL key-pair
    // party2 owning private share and HSMCL encryption of party1 share
    let (_party_one_private_share_gen, comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();

    //pi (nothing up my sleeve)
    let seed: BigInt = BigInt::from_str_radix(
        "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848",
        10,
    ).unwrap();

    let (party_one_hsmcl, hsmcl_public) =
        party_one::HSMCL::generate_keypair_and_encrypted_share_and_proof(
            &ec_key_pair_party1,
            &seed,
        );

    let party1_private =
        party_one::Party1Private::set_private_key(&ec_key_pair_party1, &party_one_hsmcl);

    let party_two_hsmcl_pub = party_two::Party2Public::verify_setup_and_zkcldl_proof(
        &hsmcl_public,
        &seed,
        &comm_witness.public_share,
    )
    .expect("proof error");

    ////////// Start Signing /////////////////
    // creating the ephemeral private shares:

    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();
    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");

    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");
    let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
    let message = BigInt::from(1234);

    let partial_sig = party_two::PartialSig::compute(
        party_two_hsmcl_pub,
        &party2_private,
        &eph_ec_key_pair_party2,
        &eph_party_one_first_message.public_share,
        &message,
    );

    let signature = party_one::Signature::compute(
        &party_one_hsmcl,
        &party1_private,
        partial_sig.c3,
        &eph_ec_key_pair_party1,
        &eph_party_two_second_message.comm_witness.public_share,
    );

    let pubkey =
        party_one::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
    party_one::verify(&signature, &pubkey, &message).expect("Invalid signature")
}
