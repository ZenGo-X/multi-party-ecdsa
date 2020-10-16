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

use crate::protocols::multi_party_ecdsa::gg_2020::blame::GlobalStatePhase5;
use crate::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters,
    PartyPrivate, SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};
use crate::utilities::mta::{MessageA, MessageB};
use crate::Error;
use serde::{Deserialize, Serialize};

use crate::protocols::multi_party_ecdsa::gg_2020::blame::GlobalStatePhase6;
use crate::protocols::multi_party_ecdsa::gg_2020::blame::GlobalStatePhase7;
use crate::protocols::multi_party_ecdsa::gg_2020::blame::LocalStatePhase5;
use crate::protocols::multi_party_ecdsa::gg_2020::blame::LocalStatePhase6;
use crate::protocols::multi_party_ecdsa::gg_2020::party_i::SignatureRecid;
use crate::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use crate::utilities::zk_pdl_with_slack::PDLwSlackProof;
use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE};
use paillier::*;
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

// Test the key generation protocol using random values for threshold and share count.
#[test]
fn test_keygen_orchestration() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut share_count_test: u16;
    let mut threshold_test: u16;
    for _count in 0..5 {
        loop {
            // 16 is just a randomly chosen value. Taking a guess as to how many shares would
            //    someone want for a key.
            share_count_test = rng.gen::<u16>() % 16;
            if share_count_test < 2 {
                continue;
            } else {
                break;
            }
        }
        loop {
            threshold_test = rng.gen::<u16>() % share_count_test;
            if threshold_test < 1 {
                continue;
            } else {
                break;
            }
        }
        println!(
            " Input params. Threshold {} Share Count {}",
            threshold_test, share_count_test
        );
        assert!(
            keygen_orchestrator(Parameters {
                share_count: share_count_test,
                threshold: threshold_test,
            })
            .is_ok(),
            format!(
                " Test failed for Threshold {} Share Count {}",
                threshold_test, share_count_test
            )
        );
    }
}

#[test]
fn test_sign_orchestration() {
    let keypairs = keygen_orchestrator(Parameters {
        share_count: 3,
        threshold: 1,
    })
    .unwrap();
    let s = [0, 1, 2];
    let sign_result = orchestrate_sign(&s[..], &vec![1, 2, 3, 4], &keypairs);
    assert!(sign_result.is_ok());
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

//
// As per page13 https://eprint.iacr.org/2020/540.pdf:
// This step will:
// 1. This participant will create a Commitment, Decommitment pair on a scalar
//    ui and then publish the Commitment part.
// 2. It will create a Paillier Keypair and publish the public key for that.
//
#[cfg(test)]
fn keygen_stage1(
    participant: usize,
) -> (
    Keys,
    KeyGenBroadcastMessage1,
    KeyGenDecommitMessage1,
    DLogStatement,
) {
    // Paillier keys and various other values
    // party_keys.ek is a secret value and it should be encrypted
    // using a key that is owned by the participant who creates it. Right now it's plaintext but
    // this is test.
    //
    let party_keys = Keys::create(participant - 1);
    let (bc1, decom) =
        party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();
    let h1_h2_N_tilde = bc1.dlog_statement.clone();
    (party_keys, bc1, decom, h1_h2_N_tilde)
}

//
// As per page 13 on https://eprint.iacr.org/2020/540.pdf:
// 1. Decommit the value obtained in stage1.
// 2. Perform a VSS on that value.
// Important to note that all the stages are sequential. Unless all the messages from the previous
// stage are not delivered, you cannot jump on the next stage.
#[cfg(test)]
fn keygen_stage2(
    participant: usize,
    params: &Parameters,
    party_keys: &[Keys],
    bc1_vec: &[KeyGenBroadcastMessage1],
    decom_vec: &[KeyGenDecommitMessage1],
) -> Result<(VerifiableSS, Vec<FE>, usize), ErrorType> {
    let vss_result = party_keys[participant - 1]
        .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
            params, decom_vec, bc1_vec,
        )?;
    let (vss_scheme, secret_shares, index) = vss_result;
    Ok((vss_scheme, secret_shares, index))
}

//
// As per page 13 on https://eprint.iacr.org/2020/540.pdf:
// 1. Participant adds there private shares to obtain their final share of the keypair.
// 2. Calculate the corresponding public key for that share.
// 3. Generate the dlog proof which the orchestrator would check later.
//
// Important to note that all the stages are sequential. Unless all the messages from the previous
// stage are not delivered, you cannot jump on the next stage.
#[cfg(test)]
fn keygen_stage3(
    party_keys: &Keys,
    vss_scheme_vec: &[VerifiableSS],
    secret_shares_vec: &Vec<Vec<FE>>,
    decom_vec: &[KeyGenDecommitMessage1],
    params: &Parameters,
    participant: usize,
    index_vec: &[usize],
) -> Result<(SharedKeys, DLogProof), ErrorType> {
    let y_vec = (0..params.share_count)
        .map(|i| decom_vec[i as usize].y_i)
        .collect::<Vec<GE>>();
    let res = party_keys.phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &params,
        &y_vec,
        &secret_shares_vec[participant - 1],
        vss_scheme_vec,
        &index_vec[participant - 1] + 1,
    )?;
    let (shared_keys, dlog_proof) = res;
    Ok((shared_keys, dlog_proof))
}
//
// Final stage of key generation. All parties must execute this.
// Unless this is successful the protocol is not complete.
//
#[cfg(test)]
fn keygen_stage4(
    params: &Parameters,
    dlog_proof_vec: &[DLogProof],
    y_vec: &[GE],
) -> Result<(), ErrorType> {
    Ok(Keys::verify_dlog_proofs(params, dlog_proof_vec, y_vec)?)
}
// The Distributed key generation protocol can work with a broadcast channel.
// All the messages are exchanged p2p.
// On the contrary, the key generation process can be orchestrated as below.
// All the participants do some work on each stage and return some data.
// This data needs to be filtered/collated and sent back as an input to the next stage.
// This test helper is just a demonstration of the same.
//
#[cfg(test)]
fn keygen_orchestrator(params: Parameters) -> Result<KeyPairResult, ErrorType> {
    let participants = (0..(params.share_count as usize))
        .map(|k| k + 1)
        .collect::<Vec<usize>>();
    // _l in all the below fields means local.
    // Just naming them differently than the structure fields so that Rust Analyzer does not
    // complain about "Shorthand Struct initialization" lint.
    //
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. party_keys.u_i
    // 2. party_keys.dk
    let mut party_keys_vec_l = vec![];
    // Nothing private in the commitment values.
    let mut bc1_vec_l = vec![];
    // Nothing private in the decommitment values.
    let mut decom_vec_l = vec![];
    // Nothing private in the below vector.
    let mut h1_h2_N_tilde_vec_l = vec![];
    for participant in participants.iter() {
        let (party_keys, bc1, decom, h1_h2_N_tilde) = keygen_stage1(*participant);
        party_keys_vec_l.push(party_keys);
        bc1_vec_l.push(bc1);
        decom_vec_l.push(decom);
        h1_h2_N_tilde_vec_l.push(h1_h2_N_tilde);
    }
    let mut vss_scheme_vec_l = vec![];
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. secret_shares_vec_l[i] -
    //    party.
    let mut secret_shares_vec_l = vec![];
    let mut index_vec = vec![];
    for participant in participants.iter() {
        let result_check = keygen_stage2(
            *participant,
            &params,
            &party_keys_vec_l,
            &bc1_vec_l,
            &decom_vec_l,
        );
        if let Err(err) = result_check {
            return Err(err);
        }
        let (vss_scheme, secret_shares, index) = result_check.unwrap();
        vss_scheme_vec_l.push(vss_scheme);
        secret_shares_vec_l.push(secret_shares);
        index_vec.push(index);
    }
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. party_shares[party_num] - all shares in this vec belong to the party number party_num.
    // one else.
    let party_shares = (0..params.share_count)
        .map(|i| {
            (0..params.share_count)
                .map(|j| {
                    let vec_j = &secret_shares_vec_l[j as usize];
                    vec_j[i as usize]
                })
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();

    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. shared_keys_vec_l.x_i - Final shard for this ECDSA keypair.
    let mut shared_keys_vec_l = vec![];
    let mut dlog_proof_vec_l = vec![];
    for participant in participants.iter() {
        let result_check = keygen_stage3(
            &party_keys_vec_l[participant - 1],
            &vss_scheme_vec_l,
            &party_shares,
            &decom_vec_l,
            &params,
            *participant,
            &index_vec,
        );
        if let Err(err) = result_check {
            return Err(err);
        }
        let (shared_keys, dlog_proof) = result_check.unwrap();
        shared_keys_vec_l.push(shared_keys);
        dlog_proof_vec_l.push(dlog_proof);
    }

    let pk_vec_l = (0..params.share_count)
        .map(|i| dlog_proof_vec_l[i as usize].pk)
        .collect::<Vec<GE>>();

    let y_vec = (0..params.share_count)
        .map(|i| decom_vec_l[i as usize].y_i)
        .collect::<Vec<GE>>();
    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum_l = tail.fold(head.clone(), |acc, x| acc + x);
    // In practice whenever this keypair will be used to sign it needs to be ensured that the below
    // stage ran successfully.
    // One way to do it would be to add a signature to the shared_keys_vec_l[i].x_i once this is
    // verified.
    for _ in participants.iter() {
        keygen_stage4(&params, &dlog_proof_vec_l, &y_vec)?;
    }
    // Important: This is only for test purposes. This code should never be executed in practice.
    //            x is the private key and all this work is done to never have that at one place in the clear.
    let xi_vec = (0..=params.threshold)
        .map(|i| shared_keys_vec_l[i as usize].x_i)
        .collect::<Vec<FE>>();
    let vss_scheme_for_test = vss_scheme_vec_l.clone();
    let x = vss_scheme_for_test[0]
        .clone()
        .reconstruct(&index_vec[0..=(params.threshold as usize)], &xi_vec);
    let sum_u_i = party_keys_vec_l
        .iter()
        .fold(FE::zero(), |acc, x| acc + x.u_i);
    assert_eq!(x, sum_u_i);
    // test code ends.

    // public vector of paillier public keys
    let e_vec_l = bc1_vec_l
        .iter()
        .map(|bc1| bc1.e.clone())
        .collect::<Vec<EncryptionKey>>();
    // At this point key generation is complete.
    // shared_keys_vec contains the private key shares for all the participants.
    Ok(KeyPairResult {
        party_keys_vec: party_keys_vec_l,
        shared_keys_vec: shared_keys_vec_l,
        pk_vec: pk_vec_l,
        y_sum: y_sum_l,
        vss_scheme: vss_scheme_for_test[0].clone(),
        e_vec: e_vec_l,
        h1_h2_N_tilde_vec: h1_h2_N_tilde_vec_l,
    })
}
fn keygen_t_n_parties(
    t: u16,
    n: u16,
) -> Result<
    (
        Vec<Keys>,
        Vec<SharedKeys>,
        Vec<GE>,
        GE,
        VerifiableSS,
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
    let y_vec = (0..n).map(|i| decom_vec[i].y_i).collect::<Vec<GE>>();
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
        index_vec.push(index);
    }

    let vss_scheme_for_test = vss_scheme_vec.clone();

    let party_shares = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| {
                    let vec_j = &secret_shares_vec[j];
                    vec_j[i]
                })
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();

    let mut shared_keys_vec = Vec::new();
    let mut dlog_proof_vec = Vec::new();
    for (i, key) in party_keys_vec.iter().enumerate() {
        let res = key.phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &y_vec,
            &party_shares[i],
            &vss_scheme_vec,
            &index_vec[i] + 1,
        );
        if res.is_err() {
            return Err(res.err().unwrap());
        }
        let (shared_keys, dlog_proof) = res.unwrap();
        shared_keys_vec.push(shared_keys);
        dlog_proof_vec.push(dlog_proof);
    }

    let pk_vec = (0..n).map(|i| dlog_proof_vec[i].pk).collect::<Vec<GE>>();

    let dlog_verification = Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &y_vec);

    if dlog_verification.is_err() {
        return Err(dlog_verification.err().unwrap());
    }
    //test
    let xi_vec = (0..=t).map(|i| shared_keys_vec[i].x_i).collect::<Vec<FE>>();
    let x = vss_scheme_for_test[0]
        .clone()
        .reconstruct(&index_vec[0..=t], &xi_vec);
    let sum_u_i = party_keys_vec.iter().fold(FE::zero(), |acc, x| acc + x.u_i);
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage1Input {
    pub vss_scheme: VerifiableSS,
    pub index: usize,
    pub s_l: Vec<usize>,
    pub party_keys: Keys,
    pub shared_keys: SharedKeys,
    pub ek: EncryptionKey,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage1Result {
    pub sign_keys: SignKeys,
    pub party_private: PartyPrivate,
    pub bc1: SignBroadcastPhase1,
    pub decom1: SignDecommitPhase1,
    pub m_a: (MessageA, BigInt),
}
// Signing stage 1.
// A sign operation happens between t+1 parties.
// The way the protocol works needs a t,t+1 share of the secret shares for all
// the participants taking part in signing.
// It also creates all the ephemeral values required for signing namely gamma_i, w_i. Those are represented by the
// SignKeys structure.
// It also creates the C, D messages for gamma_i and encrypts k_i with the Paillier key.
// Arguments:
//  pk: Public key corresponding to the keypair
//  vss_scheme_vec: Generated during keypair generation
//  index: 0 based index for the partipant.
//  s: list of participants taking part in signing.
//  keypair_result: output of the key generation protocol.
pub fn sign_stage1(input: &SignStage1Input) -> SignStage1Result {
    //t,n to t,t for it's share.
    let l_party_private =
        PartyPrivate::set_private(input.party_keys.clone(), input.shared_keys.clone());
    //ephemeral keys. w_i, gamma_i and k_i and the curve points for the same.
    let l_sign_keys = SignKeys::create(
        &l_party_private,
        &input.vss_scheme,
        input.index,
        &input.s_l[..],
    );
    // Commitment for g^gamma_i
    let (l_bc1, l_decom1) = l_sign_keys.phase1_broadcast();
    // encryption of k_i
    let l_m_a = MessageA::a(&l_sign_keys.k_i, &input.ek);
    SignStage1Result {
        sign_keys: l_sign_keys,
        party_private: l_party_private,
        bc1: l_bc1,
        decom1: l_decom1,
        m_a: l_m_a,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage2Result {
    pub gamma_i_vec: Vec<(MessageB, FE, BigInt, BigInt)>,
    pub w_i_vec: Vec<(MessageB, FE, BigInt, BigInt)>,
}
// This API will carry our the MtA for gamma_i MtAwc(Check happens later in stage3) for w_i
// This is basically a P2P between a participant and all it's peers.
pub fn sign_stage2(
    m_a: (MessageA, BigInt),
    gamma_i_vec: &[FE],
    w_i_vec: &[FE],
    e_k: &EncryptionKey,
    s_ttag: usize,
    index: usize,
) -> Result<SignStage2Result, ErrorType> {
    let mut res_gamma_i = vec![];
    let mut res_w_i = vec![];
    for j in 0..s_ttag - 1 {
        let ind = if j < index { j } else { j + 1 };
        let (m_b_gamma, beta_gamma, beta_randomness, beta_tag) =
            MessageB::b(&gamma_i_vec[ind], &e_k, m_a.0.clone());
        res_gamma_i.push((m_b_gamma, beta_gamma, beta_randomness, beta_tag));
        let (m_b_w, beta_wi, beta_randomness, beta_tag) =
            MessageB::b(&w_i_vec[ind], &e_k, m_a.0.clone());

        res_w_i.push((m_b_w, beta_wi, beta_randomness, beta_tag));
    }
    Ok(SignStage2Result {
        gamma_i_vec: res_gamma_i,
        w_i_vec: res_w_i,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage3Result {
    pub alpha_vec_gamma: Vec<(FE, BigInt)>,
    pub alpha_vec_w: Vec<(FE, BigInt)>,
}
pub fn sign_stage3(
    dk: &DecryptionKey,
    k_i: &FE,
    m_b_gamma: &[MessageB],
    m_b_w: &[MessageB],
    g_w_i: &[GE],
    index: usize,
    s_ttag: usize,
) -> Result<SignStage3Result, Error> {
    let mut res_alpha_vec_gamma = vec![];
    let mut res_alpha_vec_w = vec![];
    for i in 0..s_ttag - 1 {
        let ind = if i < index { i } else { i + 1 };
        let res = m_b_gamma[i].verify_proofs_get_alpha(dk, k_i)?;
        res_alpha_vec_gamma.push(res);
        let res = m_b_w[i].verify_proofs_get_alpha(dk, k_i)?;
        /*        if res.is_err() {
            return res;
        }*/
        if g_w_i[ind] != m_b_w[i].b_proof.pk {
            println!("MtAwc did not work i = {} ind ={}", i, ind);
            return Err(Error::InvalidCom);
        }
        res_alpha_vec_w.push(res);
    }
    Ok(SignStage3Result {
        alpha_vec_gamma: res_alpha_vec_gamma,
        alpha_vec_w: res_alpha_vec_w,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPairResult {
    pub party_keys_vec: Vec<Keys>,
    pub shared_keys_vec: Vec<SharedKeys>,
    pub pk_vec: Vec<GE>,
    pub y_sum: GE,
    pub vss_scheme: VerifiableSS,
    pub e_vec: Vec<EncryptionKey>,
    pub h1_h2_N_tilde_vec: Vec<DLogStatement>,
}
pub fn orchestrate_sign(
    s: &[usize],
    bytes_to_sign: &[u8],
    keypair_result: &KeyPairResult,
) -> Result<(), ErrorType> {
    let ttag = s.len();
    let mut private_vec = vec![];
    let mut sign_keys_vec = vec![];
    let mut bc1_vec = vec![];
    let mut decom1_vec = vec![];
    let mut m_a_vec: Vec<(MessageA, BigInt)> = vec![];
    (0..ttag).map(|i| i).for_each(|i| {
        let input = SignStage1Input {
            vss_scheme: keypair_result.vss_scheme.clone(),
            index: i,
            s_l: s.to_vec(),
            party_keys: keypair_result.party_keys_vec[i].clone(),
            shared_keys: keypair_result.shared_keys_vec[i].clone(),
            ek: keypair_result.party_keys_vec[s[i]].ek.clone(),
        };
        let res_stage1 = sign_stage1(&input);
        private_vec.push(res_stage1.party_private);
        sign_keys_vec.push(res_stage1.sign_keys);
        bc1_vec.push(res_stage1.bc1);
        decom1_vec.push(res_stage1.decom1);
        m_a_vec.push(res_stage1.m_a);
    });
    let gamma_i_vec = (0..ttag)
        .map(|i| sign_keys_vec[i].gamma_i)
        .collect::<Vec<FE>>();
    let w_i_vec = (0..ttag).map(|i| sign_keys_vec[i].w_i).collect::<Vec<FE>>();
    let mut res_stage2_vec: Vec<SignStage2Result> = vec![];
    for i in 0..ttag {
        let res = sign_stage2(
            m_a_vec[i].clone(),
            &gamma_i_vec,
            &w_i_vec,
            &keypair_result.e_vec[s[i]],
            ttag,
            i,
        );
        if let Err(err) = res {
            return Err(err);
        }
        res_stage2_vec.push(res.unwrap());
    }
    let m_b_gamma_vec_all = (0..res_stage2_vec.len())
        .map(|i| {
            res_stage2_vec[i]
                .gamma_i_vec
                .iter()
                .map(|(mb, _, _, _)| mb.clone())
                .collect::<Vec<MessageB>>()
        })
        .collect::<Vec<Vec<MessageB>>>();
    let m_b_w_vec_all = (0..res_stage2_vec.len())
        .map(|i| {
            res_stage2_vec[i]
                .w_i_vec
                .iter()
                .map(|(mb, _, _, _)| mb.clone())
                .collect::<Vec<MessageB>>()
        })
        .collect::<Vec<Vec<MessageB>>>();
    let mut res_stage3_vec: Vec<SignStage3Result> = vec![];
    let g_wi_vec: Vec<GE> = (0..ttag).map(|a| sign_keys_vec[a].g_w_i).collect();
    for i in 0..ttag {
        let res = sign_stage3(
            &keypair_result.party_keys_vec[s[i]].dk,
            &sign_keys_vec[i].k_i,
            &m_b_gamma_vec_all[i],
            &m_b_w_vec_all[i],
            &g_wi_vec,
            i,
            ttag,
        );
        if let Err(_) = res {
            return Err(ErrorType {
                error_type: "".to_string(),
                bad_actors: vec![],
            });
        }
        res_stage3_vec.push(res.unwrap());
    }
    println!("Stage 3 done.");
    let beta_vec_all = (0..res_stage2_vec.len())
        .map(|i| {
            res_stage2_vec[i]
                .gamma_i_vec
                .iter()
                .map(|(_, beta, _, _)| *beta)
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();
    let ni_vec_all = (0..res_stage2_vec.len())
        .map(|i| {
            res_stage2_vec[i]
                .w_i_vec
                .iter()
                .map(|(_, beta_wi, _, _)| *beta_wi)
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();
    let miu_vec_all = (0..res_stage3_vec.len())
        .map(|i| {
            res_stage3_vec[i]
                .alpha_vec_w
                .iter()
                .map(|(miu, _miu_bigint)| *miu)
                .collect()
        })
        .collect::<Vec<Vec<FE>>>();
    let alpha_vec_all = (0..res_stage3_vec.len())
        .map(|i| {
            res_stage3_vec[i]
                .alpha_vec_gamma
                .iter()
                .map(|(alpha, _alpha_bigint)| *alpha)
                .collect()
        })
        .collect::<Vec<Vec<FE>>>();
    let mut res_stage4_vec = vec![];
    for i in 0..ttag {
        // prepare beta_vec of party_i:
        let beta_vec = (0..ttag - 1)
            .map(|j| {
                let ind1 = if j < i { j } else { j + 1 };
                let ind2 = if j < i { i - 1 } else { i };
                let beta = beta_vec_all[ind1][ind2].clone();

                beta
            })
            .collect::<Vec<FE>>();

        // prepare ni_vec of party_i:
        let ni_vec = (0..ttag - 1)
            .map(|j| {
                let ind1 = if j < i { j } else { j + 1 };
                let ind2 = if j < i { i - 1 } else { i };
                ni_vec_all[ind1][ind2].clone()
            })
            .collect::<Vec<FE>>();
        res_stage4_vec.push(
            sign_stage4(
                &alpha_vec_all[i],
                &beta_vec,
                &miu_vec_all[i],
                &ni_vec,
                &sign_keys_vec[i],
            )
            .unwrap(),
        );
    }

    println!("Stage 4 done.");
    let delta_vec: Vec<FE> = res_stage4_vec.iter().map(|val| val.delta_i).collect();
    // all parties broadcast delta_i and compute delta_i ^(-1)
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
    let sigma_vec: Vec<FE> = res_stage4_vec.iter().map(|val| val.sigma_i).collect();
    let mut result_stage5_vec = vec![];
    for i in 0..ttag {
        let input: SignStage5Input = SignStage5Input {
            sigma_vec: sigma_vec.clone(),
            m_b_gamma_vec: m_b_gamma_vec_all[i].clone(),
            delta_inv: delta_inv.clone(),
            decom_vec1: decom1_vec.clone(),
            bc1_vec: bc1_vec.clone(),
            index: i,
            sign_keys: sign_keys_vec[i].clone(),
            s_ttag: ttag,
        };
        result_stage5_vec.push(sign_stage5(&input)?);
    }

    println!("Stage 5 done.");
    let R_vec: Vec<GE> = result_stage5_vec.iter().map(|a| a.R_vec_i).collect();
    let R_dash_vec: Vec<GE> = result_stage5_vec.iter().map(|a| a.R_dash_vec_i).collect();

    let mut res_stage6_vec = vec![];
    for i in 0..ttag {
        let input = SignStage6Input {
            R_dash: R_dash_vec[i].clone(),
            R: R_vec[i].clone(),
            m_a: m_a_vec[i].0.clone(),
            e_k: keypair_result.e_vec[s[i]].clone(),
            k_i: sign_keys_vec[i].k_i.clone(),
            randomness: m_a_vec[i].1.clone(),
            party_keys_vec: keypair_result.party_keys_vec.clone(),
            keypair_result: keypair_result.clone(),
            index: i,
            s: s.to_vec(),
        };
        let res = sign_stage6(&input)?;
        res_stage6_vec.push(res);
    }
    println!("Stage 6 done.");
    let mut phase5_proofs_vec = vec![];
    for i in 0..res_stage6_vec.len() {
        phase5_proofs_vec.push(res_stage6_vec[i].phase5_proof.clone());
    }
    //let phase5_proofs_vec = res_stage6_vec.iter().map(|a| *a.phase5_proof).collect();
    let mut res_stage7_vec = vec![];
    for i in 0..ttag {
        let input = SignStage7Input {
            phase5_proof_vec: phase5_proofs_vec[i].clone(),
            R_dash: R_dash_vec[i].clone(),
            R: R_vec[i].clone(),
            m_a: m_a_vec[i].0.clone(),
            ek: keypair_result.e_vec[s[i]].clone(),
            keypair_result: keypair_result.clone(),
            s: s.to_vec(),
            index: i,
        };
        let res = sign_stage7(&input)?;
        res_stage7_vec.push(res);
    }
    println!("Stage 7 done.");
    let message_bn_ = HSha256::create_hash(&[&BigInt::from(bytes_to_sign)]);
    let mut local_sig_vec = Vec::new();
    let mut s_vec = Vec::new();

    for i in 0..ttag {
        let input = SignStage8Input {
            R_dash_vec: R_dash_vec.clone(),
            sign_key: sign_keys_vec[i].clone(),
            message_bn: message_bn_.clone(),
            R: R_vec[i],
            sigma: sigma_vec[i],
            ysum: keypair_result.y_sum.clone(),
        };
        let check_local_sig = sign_stage8(&input);
        if check_local_sig.is_err() {
            return Err(ErrorType {
                error_type: format!(" Signature error on index {}", i),
                bad_actors: vec![],
            });
        }
        let local_sig = check_local_sig.unwrap();
        s_vec.push(local_sig.s_i.clone());
        local_sig_vec.push(local_sig);
    }

    println!("Stage 8 done.");
    let res_sig = local_sig_vec[0].output_signature(&s_vec[1..]);
    if res_sig.is_err() {
        return Err(ErrorType {
            error_type: "error in combining signatures".to_string(),
            bad_actors: vec![],
        });
    }
    let sig = res_sig.unwrap();
    check_sig(&sig.r, &sig.s, &local_sig_vec[0].m, &keypair_result.y_sum);
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage4Result {
    delta_i: FE,
    sigma_i: FE,
}
pub fn sign_stage4(
    alpha_vec: &[FE],
    beta_vec: &[FE],
    miu_vec: &[FE],
    ni_vec: &[FE],
    sign_keys: &SignKeys,
) -> Result<SignStage4Result, ErrorType> {
    Ok(SignStage4Result {
        delta_i: sign_keys.phase2_delta_i(alpha_vec, beta_vec),
        sigma_i: sign_keys.phase2_sigma_i(miu_vec, ni_vec),
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage5Input {
    pub sigma_vec: Vec<FE>,
    pub m_b_gamma_vec: Vec<MessageB>,
    pub delta_inv: FE,
    pub decom_vec1: Vec<SignDecommitPhase1>,
    pub bc1_vec: Vec<SignBroadcastPhase1>,
    pub index: usize,
    pub sign_keys: SignKeys,
    pub s_ttag: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage5Result {
    pub R_vec_i: GE,
    pub R_dash_vec_i: GE,
}
pub fn sign_stage5(input: &SignStage5Input) -> Result<SignStage5Result, ErrorType> {
    let b_proof_vec = (0..input.s_ttag - 1)
        .map(|j| &input.m_b_gamma_vec[j].b_proof)
        .collect::<Vec<&DLogProof>>();
    let check_Rvec_i = SignKeys::phase4(
        &input.delta_inv,
        &b_proof_vec,
        input.decom_vec1.clone(),
        &input.bc1_vec,
        input.index,
    );
    if check_Rvec_i.is_err() {
        println!("Error->{:?}", check_Rvec_i.clone());
        return Err(check_Rvec_i.unwrap_err());
    }
    let Rvec_i = check_Rvec_i.unwrap();
    let Rdash_vec_i = Rvec_i * input.sign_keys.k_i;
    Ok(SignStage5Result {
        R_vec_i: Rvec_i,
        R_dash_vec_i: Rdash_vec_i,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage6Input {
    pub R_dash: GE,
    pub R: GE,
    pub m_a: MessageA,
    pub randomness: BigInt,
    pub e_k: EncryptionKey,
    pub k_i: FE,
    pub party_keys_vec: Vec<Keys>,
    pub keypair_result: KeyPairResult,
    pub index: usize,
    pub s: Vec<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage6Result {
    pub phase5_proof: Vec<PDLwSlackProof>,
}
pub fn sign_stage6(input: &SignStage6Input) -> Result<SignStage6Result, ErrorType> {
    let mut proof_vec = vec![];
    let index = input.index;
    for j in 0..input.keypair_result.shared_keys_vec.len() - 1 {
        let ind = if j < index { j } else { j + 1 };
        let proof = LocalSignature::phase5_proof_pdl(
            &input.R_dash,
            &input.R,
            &input.m_a.c,
            &input.e_k,
            &input.k_i,
            &input.randomness,
            &input.party_keys_vec[input.s[index]],
            &input.keypair_result.h1_h2_N_tilde_vec[input.s[ind]],
        );

        proof_vec.push(proof);
    }

    Ok(SignStage6Result {
        phase5_proof: proof_vec,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage7Input {
    pub phase5_proof_vec: Vec<PDLwSlackProof>,
    pub R_dash: GE,
    pub R: GE,
    pub m_a: MessageA,
    pub ek: EncryptionKey,
    pub keypair_result: KeyPairResult,
    pub s: Vec<usize>,
    pub index: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage7Result {}
pub fn sign_stage7(input: &SignStage7Input) -> Result<SignStage7Result, ErrorType> {
    for _ in 0..input.keypair_result.shared_keys_vec.len() {
        let phase5_verify_zk = LocalSignature::phase5_verify_pdl(
            &input.phase5_proof_vec,
            &input.R_dash,
            &input.R,
            &input.m_a.c,
            &input.ek,
            &input.keypair_result.h1_h2_N_tilde_vec[..],
            &input.s,
            input.index,
        );
        if phase5_verify_zk.is_err() {
            return Err(phase5_verify_zk.err().unwrap());
        }
    }
    Ok(SignStage7Result {})
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage8Input {
    pub R_dash_vec: Vec<GE>,
    pub sign_key: SignKeys,
    pub message_bn: BigInt,
    pub R: GE,
    pub sigma: FE,
    pub ysum: GE,
}
pub fn sign_stage8(input: &SignStage8Input) -> Result<LocalSignature, Error> {
    let phase5_check = LocalSignature::phase5_check_R_dash_sum(&input.R_dash_vec);
    if phase5_check.is_err() {
        return Err(phase5_check.unwrap_err());
    }
    Ok(LocalSignature::phase7_local_sig(
        &input.sign_key.k_i,
        &input.message_bn,
        &input.R,
        &input.sigma,
        &input.ysum,
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
        .map(|i| SignKeys::create(&private_vec[s[i]], &vss_scheme, s[i], &s))
        .collect::<Vec<SignKeys>>();

    // each party computes [Ci,Di] = com(g^gamma_i) and broadcast the commitments
    let (bc1_vec, decommit_vec1): (Vec<_>, Vec<_>) =
        sign_keys_vec.iter().map(|k| k.phase1_broadcast()).unzip(); //number of participants //number of participants

    // each party i BROADCASTS encryption of k_i under her Paillier key
    // m_a_vec = [ma_0;ma_1;,...]
    // we assume here that party sends the same encryption to all other parties.
    // It should be changed to different encryption (randomness) to each counter party
    let m_a_vec: Vec<_> = sign_keys_vec
        .iter()
        .enumerate()
        .map(|(i, k)| MessageA::a(&k.k_i, &party_keys_vec[s[i]].ek))
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
            );
            let (m_b_w, beta_wi, _, _) =
                MessageB::b(&sign_keys_vec[ind].w_i, &ek_vec[s[i]], m_a_vec[i].0.clone());

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
                let beta = beta_vec_all[ind1][ind2].clone();

                beta
            })
            .collect::<Vec<FE>>();

        // prepare ni_vec of party_i:
        let ni_vec = (0..ttag - 1)
            .map(|j| {
                let ind1 = if j < i { j } else { j + 1 };
                let ind2 = if j < i { i - 1 } else { i };
                ni_vec_all[ind1][ind2].clone()
            })
            .collect::<Vec<FE>>();

        let mut delta = sign_keys_vec[i].phase2_delta_i(&alpha_vec_all[i], &beta_vec);

        let mut sigma = sign_keys_vec[i].phase2_sigma_i(&miu_vec_all[i], &ni_vec);
        // test wrong delta corruption
        if corrupt_step == 5 {
            if corrupted_parties.iter().find(|&&x| x == i).is_some() {
                delta = delta + &delta;
            }
        }
        // test wrong sigma corruption
        if corrupt_step == 6 {
            if corrupted_parties.iter().find(|&&x| x == i).is_some() {
                sigma = sigma + &sigma;
            }
        }
        delta_vec.push(delta);
        sigma_vec.push(sigma);
    }

    // all parties broadcast delta_i and compute delta_i ^(-1)
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
    // all parties broadcast T_i:
    let mut T_vec = Vec::new();
    let mut l_vec = Vec::new();
    for i in 0..ttag {
        let (T_i, l_i) = SignKeys::phase3_compute_t_i(&sigma_vec[i]);
        T_vec.push(T_i);
        l_vec.push(l_i);
    }
    // de-commit to g^gamma_i from phase1, test comm correctness, and that it is the same value used in MtA.
    // Return R

    let R_vec = (0..ttag)
        .map(|i| {
            // each party i tests all B = g^b = g ^ gamma_i she received.
            let m_b_gamma_vec = &m_b_gamma_vec_all[i];
            let b_proof_vec = (0..ttag - 1)
                .map(|j| &m_b_gamma_vec[j].b_proof)
                .collect::<Vec<&DLogProof>>();
            SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec1.clone(), &bc1_vec, i)
                .expect("") //TODO: propagate the error
        })
        .collect::<Vec<GE>>();

    //new phase 5
    // all parties broadcast R_dash = k_i * R.
    let R_dash_vec = (0..ttag)
        .map(|i| R_vec[i] * sign_keys_vec[i].k_i)
        .collect::<Vec<GE>>();

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
                &party_keys_vec[s[i]],
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
                k: sign_keys_vec[i].k_i,
                k_randomness: m_a_vec[i].1.clone(),
                gamma: sign_keys_vec[i].gamma_i,
                beta_randomness: beta_randomness_vec_to_test,
                beta_tag: beta_tag_vec_to_test,
                encryption_key: ek_vec[s[i]].clone(),
            };
            local_state_vec.push(local_state);
        }
        //g_gamma_vec:
        let g_gamma_vec = (0..decommit_vec1.len())
            .map(|i| decommit_vec1[i].g_gamma_i)
            .collect::<Vec<GE>>();
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
                k: sign_keys_vec[i].k_i,
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
    let message_bn = HSha256::create_hash(&[&BigInt::from(&message[..])]);
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
            if corrupted_parties.iter().find(|&&x| x == i).is_some() {
                s_vec[i] = s_vec[i] + &s_vec[i];
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
            r: local_sig_vec[0].r,
            R_dash_vec,
            m: local_sig_vec[0].m.clone(),
            R: local_sig_vec[0].R,
            S_vec,
        };
        global_state.phase7_blame()?;
    }
    //for testing purposes: checking with a second verifier:

    let sig = sig.unwrap();
    check_sig(&sig.r, &sig.s, &local_sig_vec[0].m, &y);
    return Ok(sig);
}

fn check_sig(r: &FE, s: &FE, msg: &BigInt, pk: &GE) {
    use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_vec(&msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let slice = pk.pk_to_key_slice();
    let mut raw_pk = Vec::new();
    if slice.len() != 65 {
        // after curv's pk_to_key_slice return 65 bytes, this can be removed
        raw_pk.insert(0, 4u8);
        raw_pk.extend(vec![0u8; 64 - slice.len()]);
        raw_pk.extend(slice);
    } else {
        raw_pk.extend(slice);
    }

    assert_eq!(raw_pk.len(), 65);

    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.get_element()[..];
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
