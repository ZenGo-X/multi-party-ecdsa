#[macro_use]
extern crate criterion;
extern crate curv;
extern crate multi_party_ecdsa;

mod bench {
    use criterion::Criterion;
    // use curv::arithmetic::traits::Samplable;
    // use curv::elliptic::curves::traits::*;
    // use curv::BigInt;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
    pub fn bench_full_keygen_party_one_two(c: &mut Criterion) {
        c.bench_function("keygen", move |b| {
            b.iter(|| {
                let parames = Parameters {
                    threshold: 1,
                    share_count: 2,
                };
                let party1_keys = Keys::create(0);
                let party2_keys = Keys::create(1);

                let (to_broadcast_from_party1, blind_1) =
                    party1_keys.phase1_broadcast_phase3_proof_of_correct_key();
                let (to_broadcast_from_party2, blind_2) =
                    party2_keys.phase1_broadcast_phase3_proof_of_correct_key();

                // to_broadcast_from_party1/2 is broadcasted.
                // then blind_i and y_i are broadcasted.
                // each party assembles the following vectors:
                let y_vec = vec![party1_keys.y_i.clone(), party2_keys.y_i.clone()];
                let blind_vec = vec![blind_1.clone(), blind_2.clone()];
                let bc1_vec = vec![to_broadcast_from_party1, to_broadcast_from_party2];

                // TODO: make each party verify only proofs of other parties
                //phase2 (including varifying correct paillier):
                let (vss_scheme_1, secret_shares_1, index1) = party1_keys
                    .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                        &parames, &blind_vec, //&y_vec, 
                        &bc1_vec,
                    )
                    .expect("invalid key");
                let (vss_scheme_2, secret_shares_2, index2) = party2_keys
                    .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                        &parames, &blind_vec, //&y_vec, 
                        &bc1_vec,
                    )
                    .expect("invalid key");

                // each party assembles her secret share vector:
                let vss_scheme_for_test = vss_scheme_1.clone();
                let vss_vec = vec![vss_scheme_1, vss_scheme_2];
                let party1_ss_vec = vec![
                    secret_shares_1[index1].clone(),
                    secret_shares_2[index1].clone(),
                ];
                let party2_ss_vec = vec![
                    secret_shares_1[index2].clone(),
                    secret_shares_2[index2].clone(),
                ];

                let (_shared_keys_1, dlog_proof_1) = party1_keys
                    .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                        &parames,
                        &y_vec,
                        &party1_ss_vec,
                        &vss_vec,
                        &(index1 + 1),
                    )
                    .expect("invalid vss");
                let (_shared_keys_2, dlog_proof_2) = party2_keys
                    .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                        &parames,
                        &y_vec,
                        &party2_ss_vec,
                        &vss_vec,
                        &(index2 + 1),
                    )
                    .expect("invalid vss");
                ;

                let _pk_vec = vec![dlog_proof_1.pk.clone(), dlog_proof_2.pk.clone()];
                let dlog_proof_vec = vec![dlog_proof_1, dlog_proof_2];

                //both parties run:
                Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");
            })
        });
    }
    criterion_group!{
    name = keygen;
    config = Criterion::default().sample_size(10);
    targets =self::bench_full_keygen_party_one_two}
}

criterion_main!(bench::keygen);
