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

use crate::protocols::multi_party_ecdsa::gg_2018::party_i::{
    verify, KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters,
    PartyPrivate, Phase5ADecom1, Phase5Com1, SharedKeys, SignKeys,
};
use crate::utilities::mta::{MessageA, MessageB};

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use paillier::*;
use sha2::Sha256;

#[test]
fn test_keygen_t1_n2() {
    keygen_t_n_parties(1, 2);
}

#[test]
fn test_keygen_t2_n3() {
    keygen_t_n_parties(2, 3);
}

#[test]
fn test_keygen_t2_n4() {
    keygen_t_n_parties(2, 4);
}

#[test]
fn test_sign_n5_t2_ttag4() {
    sign(2, 5, 4, vec![0, 2, 3, 4])
}
#[test]
fn test_sign_n8_t4_ttag6() {
    sign(4, 8, 6, vec![0, 1, 2, 4, 6, 7])
}

fn keygen_t_n_parties(
    t: u16,
    n: u16,
) -> (
    Vec<Keys>,
    Vec<SharedKeys>,
    Vec<Point<Secp256k1>>,
    Point<Secp256k1>,
    VerifiableSS<Secp256k1>,
) {
    let parames = Parameters {
        threshold: t,
        share_count: n,
    };
    let party_keys_vec = (0..n).map(Keys::create).collect::<Vec<Keys>>();

    let (bc1_vec, decom_vec): (Vec<_>, Vec<_>) = party_keys_vec
        .iter()
        .map(|k| k.phase1_broadcast_phase3_proof_of_correct_key())
        .unzip();

    let y_vec = (0..usize::from(n))
        .map(|i| decom_vec[i].y_i.clone())
        .collect::<Vec<Point<Secp256k1>>>();
    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);

    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();

    let vss_result: Vec<_> = party_keys_vec
        .iter()
        .map(|k| {
            k.phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &parames, &decom_vec, &bc1_vec,
            )
            .expect("invalid key")
        })
        .collect();

    for (vss_scheme, secret_shares, index) in vss_result {
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares); // cannot unzip
        index_vec.push(index as u16);
    }

    let vss_scheme_for_test = vss_scheme_vec.clone();

    let party_shares = (0..usize::from(n))
        .map(|i| {
            (0..usize::from(n))
                .map(|j| secret_shares_vec[j][i].clone())
                .collect::<Vec<Scalar<Secp256k1>>>()
        })
        .collect::<Vec<Vec<Scalar<Secp256k1>>>>();

    let mut shared_keys_vec = Vec::new();
    let mut dlog_proof_vec = Vec::new();
    for (i, key) in party_keys_vec.iter().enumerate() {
        let (shared_keys, dlog_proof) = key
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &parames,
                &y_vec,
                &party_shares[i],
                &vss_scheme_vec,
                (&index_vec[i] + 1).into(),
            )
            .expect("invalid vss");
        shared_keys_vec.push(shared_keys);
        dlog_proof_vec.push(dlog_proof);
    }

    let pk_vec = dlog_proof_vec
        .iter()
        .map(|dlog_proof| dlog_proof.pk.clone())
        .collect::<Vec<Point<Secp256k1>>>();

    //both parties run:
    Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");

    //test
    let xi_vec = shared_keys_vec
        .iter()
        .take(usize::from(t + 1))
        .map(|shared_keys| shared_keys.x_i.clone())
        .collect::<Vec<Scalar<Secp256k1>>>();
    let x = vss_scheme_for_test[0]
        .clone()
        .reconstruct(&index_vec[0..=usize::from(t)], &xi_vec);
    let sum_u_i = party_keys_vec
        .iter()
        .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + &x.u_i);
    assert_eq!(x, sum_u_i);

    (
        party_keys_vec,
        shared_keys_vec,
        pk_vec,
        y_sum,
        vss_scheme_for_test[0].clone(),
    )
}

fn sign(t: u16, n: u16, ttag: u16, s: Vec<u16>) {
    // full key gen emulation
    let (party_keys_vec, shared_keys_vec, _pk_vec, y, vss_scheme) = keygen_t_n_parties(t, n);

    let private_vec = (0..shared_keys_vec.len())
        .map(|i| PartyPrivate::set_private(party_keys_vec[i].clone(), shared_keys_vec[i].clone()))
        .collect::<Vec<PartyPrivate>>();
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
        .map(|i| SignKeys::create(&private_vec[usize::from(s[i])], &vss_scheme, s[i], &s))
        .collect::<Vec<SignKeys>>();

    // each party computes [Ci,Di] = com(g^gamma_i) and broadcast the commitments
    let (bc1_vec, decommit_vec1): (Vec<_>, Vec<_>) =
        sign_keys_vec.iter().map(|k| k.phase1_broadcast()).unzip();

    // each party i sends encryption of k_i under her Paillier key
    // m_a_vec = [ma_0;ma_1;,...]
    // range proofs are ignored here, as there's no h1, h2, N_tilde setup in this version of GG18
    let m_a_vec: Vec<_> = sign_keys_vec
        .iter()
        .enumerate()
        .map(|(i, k)| MessageA::a(&k.k_i, &party_keys_vec[usize::from(s[i])].ek, &[]).0)
        .collect();

    // each party i sends responses to m_a_vec she received (one response with input gamma_i and one with w_i)
    // m_b_gamma_vec_all is a matrix where column i is a vector of message_b's that party i answers to all ma_{j!=i} using paillier key of party j to answer to ma_j

    // aggregation of the n messages of all parties
    let mut m_b_gamma_vec_all = Vec::new();
    let mut beta_vec_all = Vec::new();
    let mut m_b_w_vec_all = Vec::new();
    let mut ni_vec_all = Vec::new();

    for (i, key) in sign_keys_vec.iter().enumerate() {
        let mut m_b_gamma_vec = Vec::new();
        let mut beta_vec = Vec::new();
        let mut m_b_w_vec = Vec::new();
        let mut ni_vec = Vec::new();

        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };

            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &key.gamma_i,
                &party_keys_vec[usize::from(s[ind])].ek,
                m_a_vec[ind].clone(),
                &[],
            )
            .unwrap();
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &key.w_i,
                &party_keys_vec[usize::from(s[ind])].ek,
                m_a_vec[ind].clone(),
                &[],
            )
            .unwrap();

            m_b_gamma_vec.push(m_b_gamma);
            beta_vec.push(beta_gamma);
            m_b_w_vec.push(m_b_w);
            ni_vec.push(beta_wi);
        }
        m_b_gamma_vec_all.push(m_b_gamma_vec.clone());
        beta_vec_all.push(beta_vec.clone());
        m_b_w_vec_all.push(m_b_w_vec.clone());
        ni_vec_all.push(ni_vec.clone());
    }

    // Here we complete the MwA protocols by taking the mb matrices and starting with the first column generating the appropriate message
    // for example for index i=0 j=0 we need party at index s[1] to answer to mb that party s[0] sent, completing a protocol between s[0] and s[1].
    //  for index i=1 j=0 we need party at index s[0] to answer to mb that party s[1]. etc.
    // IRL each party i should get only the mb messages that other parties sent in response to the party i ma's.
    // TODO: simulate as IRL
    let mut alpha_vec_all = Vec::new();
    let mut miu_vec_all = Vec::new();

    for i in 0..ttag {
        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();

        let m_b_gamma_vec_i = &m_b_gamma_vec_all[i];
        let m_b_w_vec_i = &m_b_w_vec_all[i];

        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            let m_b = m_b_gamma_vec_i[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(
                    &party_keys_vec[usize::from(s[ind])].dk,
                    &sign_keys_vec[ind].k_i,
                )
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_vec_i[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(
                    &party_keys_vec[usize::from(s[ind])].dk,
                    &sign_keys_vec[ind].k_i,
                )
                .expect("wrong dlog or m_b");

            // since we actually run two MtAwc each party needs to make sure that the values B are the same as the public values
            // here for b=w_i the parties already know W_i = g^w_i  for each party so this check is done here. for b = gamma_i the check will be later when g^gamma_i will become public
            // currently we take the W_i from the other parties signing keys
            // TODO: use pk_vec (first change from x_i to w_i) for this check.
            assert_eq!(m_b.b_proof.pk, sign_keys_vec[i].g_w_i);

            alpha_vec.push(alpha_ij_gamma);
            miu_vec.push(alpha_ij_wi);
        }
        alpha_vec_all.push(alpha_vec.clone());
        miu_vec_all.push(miu_vec.clone());
    }

    let mut delta_vec = Vec::new();
    let mut sigma_vec = Vec::new();

    for i in 0..ttag {
        let alpha_vec: Vec<Scalar<Secp256k1>> = (0..alpha_vec_all[i].len())
            .map(|j| alpha_vec_all[i][j].0.clone())
            .collect();
        let miu_vec: Vec<Scalar<Secp256k1>> = (0..miu_vec_all[i].len())
            .map(|j| miu_vec_all[i][j].0.clone())
            .collect();

        let delta = sign_keys_vec[i].phase2_delta_i(&alpha_vec[..], &beta_vec_all[i]);
        let sigma = sign_keys_vec[i].phase2_sigma_i(&miu_vec[..], &ni_vec_all[i]);
        delta_vec.push(delta);
        sigma_vec.push(sigma);
    }

    // all parties broadcast delta_i and compute delta_i ^(-1)
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    // de-commit to g^gamma_i from phase1, test comm correctness, and that it is the same value used in MtA.
    // Return R

    let _g_gamma_i_vec = (0..ttag)
        .map(|i| sign_keys_vec[i].g_gamma_i.clone())
        .collect::<Vec<Point<Secp256k1>>>();

    let R_vec = (0..ttag)
        .map(|_| {
            // each party i tests all B = g^b = g ^ gamma_i she received.
            let b_proof_vec = (0..ttag)
                .map(|j| {
                    let b_gamma_vec = &m_b_gamma_vec_all[j];
                    &b_gamma_vec[0].b_proof
                })
                .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
            SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec1.clone(), &bc1_vec)
                .expect("bad gamma_i decommit")
        })
        .collect::<Vec<Point<Secp256k1>>>();

    let message: [u8; 4] = [79, 77, 69, 82];
    let message_bn = Sha256::new()
        .chain_bigint(&BigInt::from_bytes(&message[..]))
        .result_bigint();
    let mut local_sig_vec = Vec::new();

    // each party computes s_i but don't send it yet. we start with phase5
    for i in 0..ttag {
        let local_sig = LocalSignature::phase5_local_sig(
            &sign_keys_vec[i].k_i,
            &message_bn,
            &R_vec[i],
            &sigma_vec[i],
            &y,
        );
        local_sig_vec.push(local_sig);
    }

    let mut phase5_com_vec: Vec<Phase5Com1> = Vec::new();
    let mut phase_5a_decom_vec: Vec<Phase5ADecom1> = Vec::new();
    let mut helgamal_proof_vec = Vec::new();
    let mut dlog_proof_rho_vec = Vec::new();
    // we notice that the proof for V= R^sg^l, B = A^l is a general form of homomorphic elgamal.
    for sig in &local_sig_vec {
        let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
            sig.phase5a_broadcast_5b_zkproof();
        phase5_com_vec.push(phase5_com);
        phase_5a_decom_vec.push(phase_5a_decom);
        helgamal_proof_vec.push(helgamal_proof);
        dlog_proof_rho_vec.push(dlog_proof_rho);
    }

    let mut phase5_com2_vec = Vec::new();
    let mut phase_5d_decom2_vec = Vec::new();
    for i in 0..ttag {
        let mut phase_5a_decom_vec_clone = phase_5a_decom_vec.clone();
        let mut phase_5a_com_vec_clone = phase5_com_vec.clone();
        let mut phase_5b_elgamal_vec_clone = helgamal_proof_vec.clone();

        let _decom_i = phase_5a_decom_vec_clone.remove(i);
        let _com_i = phase_5a_com_vec_clone.remove(i);
        let _elgamal_i = phase_5b_elgamal_vec_clone.remove(i);
        //        for j in 0..s_minus_i.len() {
        let (phase5_com2, phase_5d_decom2) = local_sig_vec[i]
            .phase5c(
                &phase_5a_decom_vec_clone,
                &phase_5a_com_vec_clone,
                &phase_5b_elgamal_vec_clone,
                &dlog_proof_rho_vec,
                &phase_5a_decom_vec[i].V_i,
                &R_vec[0],
            )
            .expect("error phase5");
        phase5_com2_vec.push(phase5_com2);
        phase_5d_decom2_vec.push(phase_5d_decom2);
        //        }
    }

    // assuming phase5 checks passes each party sends s_i and compute sum_i{s_i}
    let mut s_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    for sig in &local_sig_vec {
        let s_i = sig
            .phase5d(&phase_5d_decom2_vec, &phase5_com2_vec, &phase_5a_decom_vec)
            .expect("bad com 5d");
        s_vec.push(s_i);
    }

    // here we compute the signature only of party i=0 to demonstrate correctness.
    s_vec.remove(0);
    let sig = local_sig_vec[0]
        .output_signature(&s_vec)
        .expect("verification failed");

    assert_eq!(local_sig_vec[0].y, y);
    verify(&sig, &local_sig_vec[0].y, &local_sig_vec[0].m).unwrap();
    check_sig(&sig.r, &sig.s, &local_sig_vec[0].m, &y);
}

fn check_sig(r: &Scalar<Secp256k1>, s: &Scalar<Secp256k1>, msg: &BigInt, pk: &Point<Secp256k1>) {
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
    let (commit, decommit) = k.phase1_broadcast_phase3_proof_of_correct_key();

    let encoded = serde_json::to_string(&commit).unwrap();
    let decoded: KeyGenBroadcastMessage1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(commit.com, decoded.com);

    let encoded = serde_json::to_string(&decommit).unwrap();
    let decoded: KeyGenDecommitMessage1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decommit.y_i, decoded.y_i);
}
