use criterion::criterion_main;

mod bench {
    use criterion::{criterion_group, Criterion};
    use curv::BigInt;
    use multi_party_ecdsa::protocols::two_party_ecdsa::cclst_2019::party_two::HSMCLPublic;
    use multi_party_ecdsa::protocols::two_party_ecdsa::cclst_2019::*;

    pub fn bench_full_keygen_party_one_two(c: &mut Criterion) {
        c.bench_function("keygen", move |b| {
            b.iter(|| {
                let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
                    party_one::KeyGenFirstMsg::create_commitments();
                let (party_two_private_share_gen, ec_key_pair_party2) =
                    party_two::KeyGenFirstMsg::create();

                let party_one_hsmcl_key_pair =
                    party_one::HSMCLKeyPair::generate_keypair_and_encrypted_share(
                        &ec_key_pair_party1,
                    );

                let party_two_hsmcl_public = HSMCLPublic {
                    ek: party_one_hsmcl_key_pair.keypair.pk.clone(),
                    encrypted_secret_share: party_one_hsmcl_key_pair.encrypted_share.clone(),
                };
                // creating the ephemeral private shares:

                let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
                    party_two::EphKeyGenFirstMsg::create_commitments();
                let (eph_party_one_first_message, eph_ec_key_pair_party1) =
                    party_one::EphKeyGenFirstMsg::create();
                let eph_party_two_second_message =
                    party_two::EphKeyGenSecondMsg::verify_and_decommit(
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
                    party_two_hsmcl_public,
                    &party2_private,
                    &eph_ec_key_pair_party2,
                    &eph_party_one_first_message.public_share,
                    &message,
                );

                let party1_private = party_one::Party1Private::set_private_key(
                    &ec_key_pair_party1,
                    &party_one_hsmcl_key_pair,
                );

                let signature = party_one::Signature::compute(
                    &party1_private,
                    partial_sig.c3,
                    &eph_ec_key_pair_party1,
                    &eph_party_two_second_message.comm_witness.public_share,
                );

                let pubkey = party_one::compute_pubkey(
                    &party1_private,
                    &party_two_private_share_gen.public_share,
                );
                party_one::verify(&signature, &pubkey, &message).expect("Invalid signature")
            })
        });
    }

    criterion_group! {
    name = keygen;
    config = Criterion::default().sample_size(10);
    targets =self::bench_full_keygen_party_one_two}
}

criterion_main!(bench::keygen);
