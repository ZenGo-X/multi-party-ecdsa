#![allow(non_snake_case)]

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
use crate::protocols::multi_party_ecdsa::gg_2020::blame::{
    GlobalStatePhase5, GlobalStatePhase6, GlobalStatePhase7, LocalStatePhase5, LocalStatePhase6,
};
use crate::protocols::multi_party_ecdsa::gg_2020::party_i::SignatureRecid;
use crate::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters, SharedKeys,
    SignKeys,
};
use crate::utilities::mta::{MessageA, MessageB};
use curv::arithmetic::traits::Converter;

use crate::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use crate::utilities::zk_pdl_with_slack::PDLwSlackProof;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use paillier::*;
use sha2::Sha256;
use zk_paillier::zkproofs::DLogStatement;

#[test]
fn test_keygen_t1_n2() {
    assert!(keygen_t_n_parties(1, 2).is_ok());
}

#[test]
fn test_keygen_t2_n3() {
    assert!(keygen_t_n_parties(2, 3).is_ok());
}

#[test]
fn test_keygen_t2_n4() {
    assert!(keygen_t_n_parties(2, 4).is_ok());
}

#[test]
fn test_sign_n2_t1_ttag1() {
    let _ = sign(1, 2, 2, vec![0, 1], 0, &[0]);
}

#[test]
fn test_sign_n5_t2_ttag4() {
    let _ = sign(2, 5, 4, vec![0, 2, 3, 4], 0, &[0]);
}
#[test]
fn test_sign_n8_t4_ttag6() {
    let _ = sign(4, 8, 6, vec![0, 1, 2, 4, 6, 7], 0, &[0]);
}

// party 1 is corrupting step 5
#[test]
fn test_sign_n2_t1_ttag1_corrupt_step5_party1() {
    let res = sign(1, 2, 2, vec![0, 1], 5, &[0]);
    assert!(&res.err().unwrap().bad_actors[..] == &[0])
}

// party 2 is corrupting step 5
#[test]
fn test_sign_n2_t1_ttag1_corrupt_step5_party2() {
    let res = sign(1, 2, 2, vec![0, 1], 5, &[1]);
    assert!(&res.err().unwrap().bad_actors[..] == &[1])
}

// both parties are corrupting step 5
#[test]
fn test_sign_n2_t1_ttag1_corrupt_step5_party12() {
    let res = sign(1, 2, 2, vec![0, 1], 5, &[0, 1]);
    assert!(&res.err().unwrap().bad_actors[..] == &[0, 1])
}
// party 1 is corrupted
#[test]
fn test_sign_n5_t2_ttag4_corrupt_step5_party1() {
    let res = sign(2, 5, 4, vec![0, 2, 3, 4], 5, &[0]);
    assert!(&res.err().unwrap().bad_actors[..] == &[0])
}

// party 1,4 are corrupted
#[test]
fn test_sign_n5_t2_ttag4_corrupt_step5_party14() {
    let res = sign(2, 5, 4, vec![0, 2, 3, 4], 5, &[0, 3]);
    assert!(&res.err().unwrap().bad_actors[..] == &[0, 3])
}

// party 1 is corrupting step 6
#[test]
fn test_sign_n2_t1_ttag1_corrupt_step6_party1() {
    let res = sign(1, 2, 2, vec![0, 1], 6, &[0]);
    assert!(&res.err().unwrap().bad_actors[..] == &[0])
}
// party 2 is corrupting step 6
#[test]
fn test_sign_n2_t1_ttag1_corrupt_step6_party2() {
    let res = sign(1, 2, 2, vec![0, 1], 6, &[1]);
    assert!(&res.err().unwrap().bad_actors[..] == &[1])
}

// both parties are corrupting step 6
#[test]
fn test_sign_n2_t1_ttag1_corrupt_step6_party12() {
    let res = sign(1, 2, 2, vec![0, 1], 6, &[0, 1]);
    assert!(&res.err().unwrap().bad_actors[..] == &[0, 1])
}
// party 1 is corrupted
#[test]
fn test_sign_n5_t2_ttag4_corrupt_step6_party1() {
    let res = sign(2, 5, 4, vec![0, 2, 3, 4], 6, &[0]);
    assert!(&res.err().unwrap().bad_actors[..] == &[0])
}

// party 1,4 are corrupted
#[test]
fn test_sign_n5_t2_ttag4_corrupt_step6_party14() {
    let res = sign(2, 5, 4, vec![0, 2, 3, 4], 6, &[0, 3]);
    assert!(&res.err().unwrap().bad_actors[..] == &[0, 3])
}

// party 1 is corrupting step 5
#[test]
fn test_sign_n2_t1_ttag1_corrupt_step7_party2() {
    let res = sign(1, 2, 2, vec![0, 1], 7, &[1]);
    assert!(&res.err().unwrap().bad_actors[..] == &[1])
}

// party 2,4 are corrupted
#[test]
fn test_sign_n5_t2_ttag4_corrupt_step7_party24() {
    let res = sign(2, 5, 4, vec![0, 2, 3, 4], 7, &[1, 3]);
    assert!(&res.err().unwrap().bad_actors[..] == &[1, 3])
}

fn keygen_t_n_parties(
    t: u16,
    n: u16,
) -> Result<
    (
        Vec<Keys>,
        Vec<SharedKeys>,
        Vec<Point<Secp256k1>>,
        Point<Secp256k1>,
        VerifiableSS<Secp256k1>,
        Vec<EncryptionKey>,
        Vec<DLogStatement>,
    ),
    ErrorType,
> {
    let params = Parameters {
        threshold: t,
        share_count: n,
    };
    let (t, n) = (t as usize, n as usize);
    let party_keys_vec = (0..n).map(Keys::create).collect::<Vec<Keys>>();

    let (bc1_vec, decom_vec): (Vec<_>, Vec<_>) = party_keys_vec
        .iter()
        .map(|k| k.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2())
        .unzip();

    let e_vec = bc1_vec
        .iter()
        .map(|bc1| bc1.e.clone())
        .collect::<Vec<EncryptionKey>>();
    let h1_h2_N_tilde_vec = bc1_vec
        .iter()
        .map(|bc1| bc1.dlog_statement.clone())
        .collect::<Vec<DLogStatement>>();
    let y_vec = (0..n)
        .map(|i| decom_vec[i].y_i.clone())
        .collect::<Vec<Point<Secp256k1>>>();
    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);

    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();

    // TODO: find way to propagate the error and bad actors list properly
    let vss_result: Vec<_> = party_keys_vec
        .iter()
        .map(|k| {
            k.phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
                &params, &decom_vec, &bc1_vec,
            )
            .expect("")
        })
        .collect();

    for (vss_scheme, secret_shares, index) in vss_result {
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares); // cannot unzip
        index_vec.push(index as u16);
    }

    let vss_scheme_for_test = vss_scheme_vec.clone();

    let party_shares = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| {
                    let vec_j = &secret_shares_vec[j];
                    vec_j[i].clone()
                })
                .collect::<Vec<Scalar<Secp256k1>>>()
        })
        .collect::<Vec<Vec<Scalar<Secp256k1>>>>();

    let mut shared_keys_vec = Vec::new();
    let mut dlog_proof_vec = Vec::new();
    for (i, key) in party_keys_vec.iter().enumerate() {
        let res = key.phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &y_vec,
            &party_shares[i],
            &vss_scheme_vec,
            (&index_vec[i] + 1).into(),
        );
        if res.is_err() {
            return Err(res.err().unwrap());
        }
        let (shared_keys, dlog_proof) = res.unwrap();
        shared_keys_vec.push(shared_keys);
        dlog_proof_vec.push(dlog_proof);
    }

    let pk_vec = (0..n)
        .map(|i| dlog_proof_vec[i].pk.clone())
        .collect::<Vec<Point<Secp256k1>>>();

    let dlog_verification = Keys::verify_dlog_proofs_check_against_vss(
        &params,
        &dlog_proof_vec,
        &y_vec,
        &vss_scheme_vec,
    );

    if dlog_verification.is_err() {
        return Err(dlog_verification.err().unwrap());
    }
    //test
    let xi_vec = (0..=t)
        .map(|i| shared_keys_vec[i].x_i.clone())
        .collect::<Vec<Scalar<Secp256k1>>>();
    let x = vss_scheme_for_test[0]
        .clone()
        .reconstruct(&index_vec[0..=t], &xi_vec);
    let sum_u_i = party_keys_vec
        .iter()
        .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + &x.u_i);
    assert_eq!(x, sum_u_i);

    Ok((
        party_keys_vec,                 // Paillier keys, keypair, N, h1, h2
        shared_keys_vec,                // Private shares for this MPC keypair
        pk_vec,                         // dlog proof for x_i
        y_sum,                          // public key for this MPC keypair.
        vss_scheme_for_test[0].clone(), // This contains the commitments for each initial share and the shares itself
        e_vec,                          // paillier encryption keys. Why separate ?
        h1_h2_N_tilde_vec,
    ))
}

fn sign(
    t: u16,
    n: u16,
    ttag: u16,     //number of participants
    s: Vec<usize>, //participant list indexed from zero
    corrupt_step: usize,
    corrupted_parties: &[usize],
) -> Result<SignatureRecid, ErrorType> {
    // full key gen emulation
    let (party_keys_vec, shared_keys_vec, pk_vec, y, vss_scheme, ek_vec, dlog_statement_vec) =
        keygen_t_n_parties(t, n).unwrap();

    // transform the t,n share to t,t+1 share. Get the public keys for the same.
    let g_w_vec = SignKeys::g_w_vec(&pk_vec, &s[..], &vss_scheme);

    let private_vec = (0..shared_keys_vec.len())
        .map(|i| shared_keys_vec[i].x_i.clone())
        .collect::<Vec<_>>();
    // make sure that we have t<t'<n and the group s contains id's for t' parties
    // TODO: make sure s has unique id's and they are all in range 0..n
    // TODO: make sure this code can run when id's are not in ascending order
    assert!(ttag > t);
    let ttag = ttag as usize;
    assert_eq!(s.len(), ttag);

    // each party creates a signing key. This happens in parallel IRL. In this test we
    // create a vector of signing keys, one for each party.
    // throughout i will index parties
    let sign_keys_vec = (0..ttag)
        .map(|i| SignKeys::create(&private_vec[s[i]], &vss_scheme, s[i], &s))
        .collect::<Vec<SignKeys>>();

    // each party computes [Ci,Di] = com(g^gamma_i) and broadcast the commitments
    let (bc1_vec, decommit_vec1): (Vec<_>, Vec<_>) =
        sign_keys_vec.iter().map(|k| k.phase1_broadcast()).unzip();

    // each signer's dlog statement. in reality, parties prove statements
    // using only other parties' h1,h2,N_tilde. here we also use own parameters for simplicity
    let signers_dlog_statements = (0..ttag)
        .map(|i| dlog_statement_vec[s[i]].clone())
        .collect::<Vec<DLogStatement>>();

    // each party i BROADCASTS encryption of k_i under her Paillier key
    // m_a_vec = [ma_0;ma_1;,...]
    // we assume here that party sends the same encryption to all other parties.
    // It should be changed to different encryption (randomness) to each counter party
    let m_a_vec: Vec<_> = sign_keys_vec
        .iter()
        .enumerate()
        .map(|(i, k)| MessageA::a(&k.k_i, &party_keys_vec[s[i]].ek, &signers_dlog_statements))
        .collect();

    // #each party i sends responses to m_a_vec she received (one response with input gamma_i and one with w_i)
    // #m_b_gamma_vec_all is a matrix where column i is a vector of message_b's that were sent to party i

    // aggregation of the n messages of all parties
    let mut m_b_gamma_vec_all = Vec::new();
    let mut beta_vec_all = Vec::new();
    let mut m_b_w_vec_all = Vec::new();
    let mut ni_vec_all = Vec::new();
    let mut beta_randomness_vec_all = Vec::new(); //should be accessible in case of blame
    let mut beta_tag_vec_all = Vec::new(); //should be accessible in case of blame

    // m_b_gamma and m_b_w are BROADCAST
    for i in 0..ttag {
        let mut m_b_gamma_vec = Vec::new();
        let mut beta_vec = Vec::new();
        let mut beta_randomness_vec = Vec::new();
        let mut beta_tag_vec = Vec::new();
        let mut m_b_w_vec = Vec::new();
        let mut ni_vec = Vec::new();

        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            let (m_b_gamma, beta_gamma, beta_randomness, beta_tag) = MessageB::b(
                &sign_keys_vec[ind].gamma_i,
                &ek_vec[s[i]],
                m_a_vec[i].0.clone(),
                &signers_dlog_statements,
            )
            .expect("Alice's range proofs in MtA failed");
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &sign_keys_vec[ind].w_i,
                &ek_vec[s[i]],
                m_a_vec[i].0.clone(),
                &signers_dlog_statements,
            )
            .expect("Alice's range proofs in MtA failed");

            m_b_gamma_vec.push(m_b_gamma);
            beta_vec.push(beta_gamma);
            beta_randomness_vec.push(beta_randomness);
            beta_tag_vec.push(beta_tag);
            m_b_w_vec.push(m_b_w);
            ni_vec.push(beta_wi);
        }
        m_b_gamma_vec_all.push(m_b_gamma_vec.clone());
        beta_vec_all.push(beta_vec.clone());
        beta_tag_vec_all.push(beta_tag_vec.clone());
        beta_randomness_vec_all.push(beta_randomness_vec.clone());
        m_b_w_vec_all.push(m_b_w_vec.clone());
        ni_vec_all.push(ni_vec.clone());
    }

    // Here we complete the MwA protocols by taking the mb matrices and starting with the first column,
    // generating the appropriate message. The first column is the answers of party 1 to mb sent from other parties.
    // The second column is the answers that party 2 is sending and so on.

    // TODO: simulate as IRL
    let mut alpha_vec_all = Vec::new();
    let mut miu_vec_all = Vec::new();
    let mut miu_bigint_vec_all = Vec::new(); //required for the phase6 IA sub protocol

    for i in 0..ttag {
        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();
        let mut miu_bigint_vec = Vec::new(); //required for the phase6 IA sub protocol

        let m_b_gamma_vec_i = &m_b_gamma_vec_all[i];
        let m_b_w_vec_i = &m_b_w_vec_all[i];

        // in case
        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            let m_b = m_b_gamma_vec_i[j].clone();

            // TODO: identify these errors
            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&party_keys_vec[s[i]].dk, &sign_keys_vec[i].k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_vec_i[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&party_keys_vec[s[i]].dk, &sign_keys_vec[i].k_i)
                .expect("wrong dlog or m_b");

            // since we actually run two MtAwc each party needs to make sure that the values B are the same as the public values
            // here for b=w_i the parties already know W_i = g^w_i  for each party so this check is done here. for b = gamma_i the check will be later when g^gamma_i will become public
            // currently we take the W_i from the other parties signing keys
            // TODO: use pk_vec (first change from x_i to w_i) for this check.
            assert_eq!(m_b.b_proof.pk, sign_keys_vec[ind].g_w_i);

            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            miu_bigint_vec.push(alpha_ij_wi.1);
        }
        alpha_vec_all.push(alpha_vec.clone());
        miu_vec_all.push(miu_vec.clone());
        miu_bigint_vec_all.push(miu_bigint_vec.clone());
    }

    let mut delta_vec = Vec::new();
    let mut sigma_vec = Vec::new();

    for i in 0..ttag {
        // prepare beta_vec of party_i:
        let beta_vec = (0..ttag - 1)
            .map(|j| {
                let ind1 = if j < i { j } else { j + 1 };
                let ind2 = if j < i { i - 1 } else { i };

                beta_vec_all[ind1][ind2].clone()
            })
            .collect::<Vec<Scalar<Secp256k1>>>();

        // prepare ni_vec of party_i:
        let ni_vec = (0..ttag - 1)
            .map(|j| {
                let ind1 = if j < i { j } else { j + 1 };
                let ind2 = if j < i { i - 1 } else { i };
                ni_vec_all[ind1][ind2].clone()
            })
            .collect::<Vec<Scalar<Secp256k1>>>();

        let mut delta = sign_keys_vec[i].phase2_delta_i(&alpha_vec_all[i], &beta_vec);

        let mut sigma = sign_keys_vec[i].phase2_sigma_i(&miu_vec_all[i], &ni_vec);
        // test wrong delta corruption
        if corrupt_step == 5 && corrupted_parties.iter().any(|&x| x == i) {
            delta = &delta + &delta;
        }
        // test wrong sigma corruption
        if corrupt_step == 6 && corrupted_parties.iter().any(|&x| x == i) {
            sigma = &sigma + &sigma;
        }
        delta_vec.push(delta);
        sigma_vec.push(sigma);
    }

    // all parties broadcast delta_i and compute delta_i ^(-1)
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
    // all parties broadcast T_i:
    let mut T_vec = Vec::new();
    let mut l_vec = Vec::new();
    let mut T_proof_vec = Vec::new();
    for i in 0..ttag {
        let (T_i, l_i, T_proof_i) = SignKeys::phase3_compute_t_i(&sigma_vec[i]);
        T_vec.push(T_i);
        l_vec.push(l_i);
        T_proof_vec.push(T_proof_i);
    }
    // verify T_proof_vec
    for i in 0..ttag {
        PedersenProof::verify(&T_proof_vec[i]).expect("error T proof");
    }
    // de-commit to g^gamma_i from phase1, test comm correctness, and that it is the same value used in MtA.
    // Return R

    let R_vec = (0..ttag)
        .map(|i| {
            // each party i tests all B = g^b = g ^ gamma_i she received.
            let m_b_gamma_vec = &m_b_gamma_vec_all[i];
            let b_proof_vec = (0..ttag - 1)
                .map(|j| &m_b_gamma_vec[j].b_proof)
                .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
            SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec1.clone(), &bc1_vec, i)
                .expect("") //TODO: propagate the error
        })
        .collect::<Vec<Point<Secp256k1>>>();

    //new phase 5
    // all parties broadcast R_dash = k_i * R.
    let R_dash_vec = (0..ttag)
        .map(|i| &R_vec[i] * &sign_keys_vec[i].k_i)
        .collect::<Vec<Point<Secp256k1>>>();

    // each party sends first message to all other parties
    let mut phase5_proofs_vec: Vec<Vec<PDLwSlackProof>> = vec![Vec::new(); ttag];
    for i in 0..ttag {
        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            let proof = LocalSignature::phase5_proof_pdl(
                &R_dash_vec[i],
                &R_vec[i],
                &m_a_vec[i].0.c,
                &ek_vec[s[i]],
                &sign_keys_vec[i].k_i,
                &m_a_vec[i].1,
                &dlog_statement_vec[s[ind]],
            );

            phase5_proofs_vec[i].push(proof);
        }
    }

    for i in 0..ttag {
        let phase5_verify_zk = LocalSignature::phase5_verify_pdl(
            &phase5_proofs_vec[i],
            &R_dash_vec[i],
            &R_vec[i],
            &m_a_vec[i].0.c,
            &ek_vec[s[i]],
            &dlog_statement_vec[..],
            &s,
            i,
        );
        if phase5_verify_zk.is_err() {
            return Err(phase5_verify_zk.err().unwrap());
        }
    }

    //each party must run the test
    let phase5_check = LocalSignature::phase5_check_R_dash_sum(&R_dash_vec);
    if phase5_check.is_err() {
        // initiate phase 5 blame protocol to learn which parties acted maliciously.
        // each party generates local state and share with other parties.
        // assuming sync communication - if a message was failed to arrive from a party -
        // this party should automatically be blamed
        let mut local_state_vec = Vec::new();
        for i in 0..ttag {
            // compose beta tag vector:
            let mut beta_tag_vec_to_test = Vec::new();
            let mut beta_randomness_vec_to_test = Vec::new();
            for j in 0..ttag - 1 {
                let ind1 = if j < i { j } else { j + 1 };
                let ind2 = if j < i { i - 1 } else { i };
                beta_tag_vec_to_test.push(beta_tag_vec_all[ind1][ind2].clone());
                beta_randomness_vec_to_test.push(beta_randomness_vec_all[ind1][ind2].clone());
            }

            let local_state = LocalStatePhase5 {
                k: sign_keys_vec[i].k_i.clone(),
                k_randomness: m_a_vec[i].1.clone(),
                gamma: sign_keys_vec[i].gamma_i.clone(),
                beta_randomness: beta_randomness_vec_to_test,
                beta_tag: beta_tag_vec_to_test,
                encryption_key: ek_vec[s[i]].clone(),
            };
            local_state_vec.push(local_state);
        }
        //g_gamma_vec:
        let g_gamma_vec = (0..decommit_vec1.len())
            .map(|i| decommit_vec1[i].g_gamma_i.clone())
            .collect::<Vec<Point<Secp256k1>>>();
        //m_a_vec
        let m_a_vec = (0..m_a_vec.len())
            .map(|i| m_a_vec[i].0.clone())
            .collect::<Vec<MessageA>>();

        // reduce ek vec to only ek of participants :
        let ek_vec = (0..ttag)
            .map(|k| ek_vec[s[k]].clone())
            .collect::<Vec<EncryptionKey>>();
        let global_state = GlobalStatePhase5::local_state_to_global_state(
            &ek_vec[..],
            &delta_vec,
            &g_gamma_vec[..],
            &m_a_vec[..],
            m_b_gamma_vec_all,
            &local_state_vec[..],
        );
        global_state.phase5_blame()?;
    }

    let mut S_vec = Vec::new();
    let mut homo_elgamal_proof_vec = Vec::new();
    for i in 0..ttag {
        let (S_i, homo_elgamal_proof) = LocalSignature::phase6_compute_S_i_and_proof_of_consistency(
            &R_vec[i],
            &T_vec[i],
            &sigma_vec[i],
            &l_vec[i],
        );
        S_vec.push(S_i);
        homo_elgamal_proof_vec.push(homo_elgamal_proof);
    }

    LocalSignature::phase6_verify_proof(&S_vec, &homo_elgamal_proof_vec, &R_vec, &T_vec)?;

    let phase6_check = LocalSignature::phase6_check_S_i_sum(&y, &S_vec);
    if phase6_check.is_err() {
        // initiate phase 6 blame protocol to learn which parties acted maliciously.
        // each party generates local state and share with other parties.
        // assuming sync communication - if a message was failed to arrive from a party -
        // this party should automatically be blamed

        let mut local_state_vec = Vec::new();
        for i in 0..ttag {
            let mut miu_randomness_vec = Vec::new();
            for j in 0..ttag - 1 {
                let rand = GlobalStatePhase6::extract_paillier_randomness(
                    &m_b_w_vec_all[i][j].c,
                    &party_keys_vec[s[i]].dk,
                );
                miu_randomness_vec.push(rand);
            }
            let proof = GlobalStatePhase6::ecddh_proof(&sigma_vec[i], &R_vec[i], &S_vec[i]);
            let local_state = LocalStatePhase6 {
                k: sign_keys_vec[i].k_i.clone(),
                k_randomness: m_a_vec[i].1.clone(),
                miu: miu_bigint_vec_all[i].clone(),
                miu_randomness: miu_randomness_vec,
                proof_of_eq_dlog: proof,
            };
            local_state_vec.push(local_state);
        }

        //m_a_vec
        let m_a_vec = (0..m_a_vec.len())
            .map(|i| m_a_vec[i].0.clone())
            .collect::<Vec<MessageA>>();

        // reduce ek vec to only ek of participants :
        let ek_vec = (0..ttag)
            .map(|k| ek_vec[s[k]].clone())
            .collect::<Vec<EncryptionKey>>();

        let global_state = GlobalStatePhase6::local_state_to_global_state(
            &ek_vec[..],
            &S_vec[..],
            &g_w_vec[..],
            &m_a_vec[..],
            m_b_w_vec_all,
            &local_state_vec[..],
        );
        global_state.phase6_blame(&R_vec[0])?;
    }

    let message: [u8; 4] = [79, 77, 69, 82];
    let message_bn = Sha256::new()
        .chain_bigint(&BigInt::from_bytes(&message[..]))
        .result_bigint();
    let mut local_sig_vec = Vec::new();
    let mut s_vec = Vec::new();
    // each party computes s_i
    for i in 0..ttag {
        let local_sig = LocalSignature::phase7_local_sig(
            &sign_keys_vec[i].k_i,
            &message_bn,
            &R_vec[i],
            &sigma_vec[i],
            &y,
        );
        s_vec.push(local_sig.s_i.clone());
        local_sig_vec.push(local_sig);
    }

    // test corrupted local s
    if corrupt_step == 7 {
        for i in 0..s_vec.len() {
            if corrupted_parties.iter().any(|&x| x == i) {
                s_vec[i] = &s_vec[i] + &s_vec[i];
            }
        }
    }

    let sig = local_sig_vec[0].output_signature(&s_vec[1..]);

    // test
    assert_eq!(local_sig_vec[0].y, y);
    //error in phase 7:
    if sig.is_err() {
        let global_state = GlobalStatePhase7 {
            s_vec,
            r: local_sig_vec[0].r.clone(),
            R_dash_vec,
            m: local_sig_vec[0].m.clone(),
            R: local_sig_vec[0].R.clone(),
            S_vec,
        };
        global_state.phase7_blame()?;
    }
    //for testing purposes: checking with a second verifier:

    let sig = sig.unwrap();
    check_sig(&sig.r, &sig.s, &local_sig_vec[0].m, &y);
    Ok(sig)
}

pub fn check_sig(
    r: &Scalar<Secp256k1>,
    s: &Scalar<Secp256k1>,
    msg: &BigInt,
    pk: &Point<Secp256k1>,
) {
    use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_bytes(msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let slice = pk.to_bytes(false);
    let mut raw_pk = Vec::new();
    if slice.len() != 65 {
        // after curv's pk_to_key_slice return 65 bytes, this can be removed
        raw_pk.insert(0, 4u8);
        raw_pk.extend(vec![0u8; 64 - slice.len()]);
        raw_pk.extend(slice.as_ref());
    } else {
        raw_pk.extend(slice.as_ref());
    }

    assert_eq!(raw_pk.len(), 65);

    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.to_bytes()[..];
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.to_bytes()[..];
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::parse_slice(compact.as_slice()).unwrap();

    let is_correct = verify(&msg, &secp_sig, &pk);
    assert!(is_correct);
}
#[test]
fn test_serialize_deserialize() {
    use serde_json;

    let k = Keys::create(0);
    let (commit, decommit) = k.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

    let encoded = serde_json::to_string(&commit).unwrap();
    let decoded: KeyGenBroadcastMessage1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(commit.com, decoded.com);

    let encoded = serde_json::to_string(&decommit).unwrap();
    let decoded: KeyGenDecommitMessage1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decommit.y_i, decoded.y_i);
}
#[test]
fn test_small_paillier() {
    // parties shouldn't be able to choose small Paillier modulus
    let mut k = Keys::create(0);
    // creating 2046-bit Paillier
    let (ek, dk) = Paillier::keypair_with_modulus_size(2046).keys();
    k.dk = dk;
    k.ek = ek;
    let (commit, decommit) = k.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();
    assert!(k
        .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
            &Parameters {
                threshold: 0,
                share_count: 1
            },
            &[decommit],
            &[commit],
        )
        .is_err());
}
