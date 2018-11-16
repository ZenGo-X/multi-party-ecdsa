#[macro_use]
extern crate criterion;
extern crate cryptography_utils;
extern crate multi_party_ecdsa;

mod bench {
    use criterion::Criterion;
    //use cryptography_utils::arithmetic::traits::Samplable;
    //use cryptography_utils::elliptic::curves::traits::*;
    //use cryptography_utils::BigInt;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;

    // benchmark function for full keygen
    pub fn bench_full_keygen_multi_party(c: &mut Criterion){

        let _threshold = 3;
        let _share_count = 5;

        c.bench_function("multi_party_keygen", move |b| {
            b.iter(|| {
                self::multi_party_keygen(_threshold, _share_count);
            })
        });
    }

    // multi party keygen (t -threshold, s - secret share count)
    pub fn multi_party_keygen(t: usize, s: usize) {
        let parames = Parameters {
            threshold: t,
            share_count: s,
        };

        let mut keys_vec = vec![];
        let mut y_vec= vec![];
        let mut blind_vec = vec![];
        let mut bc1_vec = vec![];

        for i in 0..parames.share_count {
            let party_i_keys = Keys::create(i);

            let (to_broadcast_from_party_i, blind_i) =
                party_i_keys.phase1_broadcast_phase3_proof_of_correct_key();

            y_vec.push(party_i_keys.y_i.clone());
            keys_vec.push(party_i_keys);
            blind_vec.push(blind_i.clone());
            bc1_vec.push(to_broadcast_from_party_i);

        }


        let mut vss_vec = vec![];
        let mut secret_shares_vec = vec![];
        let mut indexes_vec = vec![];

        for i in 0..parames.share_count {

            let (vss_scheme_i, secret_shares_i, index_i) = keys_vec[i]
                .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                    &parames, &blind_vec, &y_vec, &bc1_vec,
                )
                .expect("invalid key");


            vss_vec.push(vss_scheme_i.clone());
            secret_shares_vec.push(secret_shares_i.clone());
            indexes_vec.push(index_i.clone());

        }

        let mut dlog_proof_vec = vec![];

        for i in 0..parames.share_count{
            let mut party_i_ss_vec = vec![];

            for j in 0..secret_shares_vec.len(){
                party_i_ss_vec.push(secret_shares_vec[j][indexes_vec[i]].clone())
            };

            let (_shared_keys_i, dlog_proof_i) = keys_vec[i]
                .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                    &parames,
                    &y_vec,
                    &party_i_ss_vec,
                    &vss_vec,
                    &(indexes_vec[i] + 1),
                )
                .expect("invalid vss");

            dlog_proof_vec.push(dlog_proof_i.clone());


        };

        // all parties run:
        Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");
    }

    criterion_group!{
    name = keygen;
    config = Criterion::default().sample_size(10);
    targets = self::bench_full_keygen_multi_party}
}

criterion_main!(bench::keygen);
