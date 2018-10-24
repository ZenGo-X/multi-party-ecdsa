/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

#[cfg(test)]
mod tests {

    use protocols::multi_party_ecdsa::gg_2018::party_i::*;

    #[test]
    fn test_keygen_two_parties() {
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
                &parames, &blind_vec, &y_vec, &bc1_vec,
            )
            .expect("invalid key");
        let (vss_scheme_2, secret_shares_2, index2) = party2_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &parames, &blind_vec, &y_vec, &bc1_vec,
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

        let (shared_keys_1, dlog_proof_1) = party1_keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &parames,
                &y_vec,
                &party1_ss_vec,
                &vss_vec,
                &(index1 + 1),
            )
            .expect("invalid vss");
        let (shared_keys_2, dlog_proof_2) = party2_keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &parames,
                &y_vec,
                &party2_ss_vec,
                &vss_vec,
                &(index2 + 1),
            )
            .expect("invalid vss");;

        let _pk_vec = vec![dlog_proof_1.pk.clone(), dlog_proof_2.pk.clone()];
        let dlog_proof_vec = vec![dlog_proof_1, dlog_proof_2];

        //both parties run:
        Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");

        //test
        let x = vss_scheme_for_test
            .reconstruct(&vec![0, 1], &vec![shared_keys_1.x_i, shared_keys_2.x_i]);
        let sum_u_i = party1_keys.u_i + party2_keys.u_i;
        assert_eq!(x, sum_u_i);
    }

    #[test]
    fn test_keygen_n3_t2() {
        let parames = Parameters {
            threshold: 2,
            share_count: 3,
        };
        let party1_keys = Keys::create(0);
        let party2_keys = Keys::create(1);
        let party3_keys = Keys::create(2);

        let (to_broadcast_from_party1, blind_1) =
            party1_keys.phase1_broadcast_phase3_proof_of_correct_key();
        let (to_broadcast_from_party2, blind_2) =
            party2_keys.phase1_broadcast_phase3_proof_of_correct_key();
        let (to_broadcast_from_party3, blind_3) =
            party3_keys.phase1_broadcast_phase3_proof_of_correct_key();
        // to_broadcast_from_party1/2 is broadcasted.
        // then blind_i and y_i are broadcasted.
        // each party assembles the following vectors:
        let y_vec = vec![
            party1_keys.y_i.clone(),
            party2_keys.y_i.clone(),
            party3_keys.y_i.clone(),
        ];
        let blind_vec = vec![blind_1.clone(), blind_2.clone(), blind_3.clone()];
        let bc1_vec = vec![
            to_broadcast_from_party1,
            to_broadcast_from_party2,
            to_broadcast_from_party3,
        ];

        // TODO: make each party verify only proofs of other parties
        //phase2 (including varifying correct paillier):
        let (vss_scheme_1, secret_shares_1, index1) = party1_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &parames, &blind_vec, &y_vec, &bc1_vec,
            )
            .expect("invalid key");
        let (vss_scheme_2, secret_shares_2, index2) = party2_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &parames, &blind_vec, &y_vec, &bc1_vec,
            )
            .expect("invalid key");
        let (vss_scheme_3, secret_shares_3, index3) = party3_keys
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &parames, &blind_vec, &y_vec, &bc1_vec,
            )
            .expect("invalid key");

        // each party assembles her secret share vector:
        let vss_scheme_for_test = vss_scheme_1.clone();
        let vss_vec = vec![vss_scheme_1, vss_scheme_2, vss_scheme_3];
        let party1_ss_vec = vec![
            secret_shares_1[index1].clone(),
            secret_shares_2[index1].clone(),
            secret_shares_3[index1].clone(),
        ];
        let party2_ss_vec = vec![
            secret_shares_1[index2].clone(),
            secret_shares_2[index2].clone(),
            secret_shares_3[index2].clone(),
        ];
        let party3_ss_vec = vec![
            secret_shares_1[index3].clone(),
            secret_shares_2[index3].clone(),
            secret_shares_3[index3].clone(),
        ];

        let (shared_keys_1, dlog_proof_1) = party1_keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &parames,
                &y_vec,
                &party1_ss_vec,
                &vss_vec,
                &(index1 + 1),
            )
            .expect("invalid vss");
        let (shared_keys_2, dlog_proof_2) = party2_keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &parames,
                &y_vec,
                &party2_ss_vec,
                &vss_vec,
                &(index2 + 1),
            )
            .expect("invalid vss");;
        let (shared_keys_3, dlog_proof_3) = party3_keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &parames,
                &y_vec,
                &party3_ss_vec,
                &vss_vec,
                &(index3 + 1),
            )
            .expect("invalid vss");;

        let _pk_vec = vec![
            dlog_proof_1.pk.clone(),
            dlog_proof_2.pk.clone(),
            dlog_proof_3.pk.clone(),
        ];
        let dlog_proof_vec = vec![dlog_proof_1, dlog_proof_2, dlog_proof_3];

        //both parties run:
        Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");

        //test
        let x = vss_scheme_for_test.reconstruct(
            &vec![0, 1, 2],
            &vec![shared_keys_1.x_i, shared_keys_2.x_i, shared_keys_3.x_i],
        );
        let sum_u_i = party1_keys.u_i + party2_keys.u_i + party3_keys.u_i;
        assert_eq!(x, sum_u_i);
    }
}
