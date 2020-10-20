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
//!
//! This module is enabled by enabling the feature orchestrategg20.
//!
//! Using a couple of tests this module demonstrates a way that you could use the library
//! and build an actual application out of the implementation.
//! Both the Key Generation and Signing operations are divided into different stages.
//!
//! All the stages are sequential.
//! Usually the input of one stage is one of the output values of a prior stage.
//!
//! Each input and output for a stage is defined as a structure.
//! Using serde_json, this could easily be made a json.
//!
//! Then each stage API basically resembles an HTTP API for a server that would be one of the
//! parties to this Distributed Key Generation or Signing Protocol.
//!
//! A note: _l or _s after many variable names in this API is to make rust_analyzer happy.
//! If We initiaize a structure using vars with names same as member names, rust analyzer complains
//! with:
//!     shorthand struct initiailization error.
//!
use crate::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters,
    PartyPrivate, SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};
use crate::protocols::multi_party_ecdsa::gg_2020::test::check_sig;
use crate::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use crate::utilities::mta::{MessageA, MessageB};
use crate::utilities::zk_pdl_with_slack::PDLwSlackProof;
use crate::Error;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE};
use paillier::*;
use serde::{Deserialize, Serialize};
use serde_json;
use std::env::var_os;
use std::fs::File;
use std::io::Write;
use zk_paillier::zkproofs::DLogStatement;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage1Input {
    pub index: usize, // participant indexes start from zero.
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage1Result {
    pub party_keys_l: Keys,
    pub bc_com1_l: KeyGenBroadcastMessage1,
    pub decom1_l: KeyGenDecommitMessage1,
    pub h1_h2_N_tilde_l: DLogStatement,
}
//
// As per page13 https://eprint.iacr.org/2020/540.pdf:
// This step will:
// 1. This participant will create a Commitment, Decommitment pair on a scalar
//    ui and then publish the Commitment part.
// 2. It will create a Paillier Keypair and publish the public key for that.
//
pub fn keygen_stage1(input: &KeyGenStage1Input) -> KeyGenStage1Result {
    // Paillier keys and various other values
    // party_keys.ek is a secret value and it should be encrypted
    // using a key that is owned by the participant who creates it. Right now it's plaintext but
    // this is test.
    //
    let party_keys = Keys::create(input.index);
    let (bc1, decom) =
        party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();
    let h1_h2_N_tilde = bc1.dlog_statement.clone();
    KeyGenStage1Result {
        party_keys_l: party_keys,
        bc_com1_l: bc1,
        decom1_l: decom,
        h1_h2_N_tilde_l: h1_h2_N_tilde,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage2Input {
    pub index: usize,
    pub params_s: Parameters,
    pub party_keys_s: Vec<Keys>,
    pub bc1_vec_s: Vec<KeyGenBroadcastMessage1>,
    pub decom1_vec_s: Vec<KeyGenDecommitMessage1>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage2Result {
    pub vss_scheme_s: VerifiableSS,
    pub secret_shares_s: Vec<FE>,
    pub index_s: usize,
}
//
// As per page 13 on https://eprint.iacr.org/2020/540.pdf:
// 1. Decommit the value obtained in stage1.
// 2. Perform a VSS on that value.

pub fn keygen_stage2(input: &KeyGenStage2Input) -> Result<KeyGenStage2Result, ErrorType> {
    let vss_result = input.party_keys_s[input.index]
        .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
            &input.params_s,
            &input.decom1_vec_s,
            &input.bc1_vec_s,
        )?;
    let (vss_scheme, secret_shares, index) = vss_result;
    Ok(KeyGenStage2Result {
        vss_scheme_s: vss_scheme,
        secret_shares_s: secret_shares,
        index_s: index,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage3Input {
    pub party_keys_s: Keys,
    pub vss_scheme_vec_s: Vec<VerifiableSS>,
    pub secret_shares_vec_s: Vec<FE>,
    pub y_vec_s: Vec<GE>,
    pub params_s: Parameters,
    pub index_s: usize,
    pub index_vec_s: Vec<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage3Result {
    pub shared_keys_s: SharedKeys,
    pub dlog_proof_s: DLogProof,
}
//
// As per page 13 on https://eprint.iacr.org/2020/540.pdf:
// 1. Participant adds there private shares to obtain their final share of the keypair.
// 2. Calculate the corresponding public key for that share.
// 3. Generate the dlog proof which the orchestrator would check later.
//
// Important to note that all the stages are sequential. Unless all the messages from the previous
// stage are not delivered, you cannot jump on the next stage.

fn keygen_stage3(input: &KeyGenStage3Input) -> Result<KeyGenStage3Result, ErrorType> {
    let res = input
        .party_keys_s
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &input.params_s,
            &input.y_vec_s,
            &input.secret_shares_vec_s,
            &input.vss_scheme_vec_s,
            &input.index_vec_s[input.index_s] + 1,
        )?;
    let (shared_keys, dlog_proof) = res;
    Ok(KeyGenStage3Result {
        shared_keys_s: shared_keys,
        dlog_proof_s: dlog_proof,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenStage4Input {
    pub params_s: Parameters,
    pub dlog_proof_vec_s: Vec<DLogProof>,
    pub y_vec_s: Vec<GE>,
}

//
// Final stage of key generation. All parties must execute this.
// Unless this is successful the protocol is not complete.
//
pub fn keygen_stage4(input: &KeyGenStage4Input) -> Result<(), ErrorType> {
    let result = Keys::verify_dlog_proofs(&input.params_s, &input.dlog_proof_vec_s, &input.y_vec_s);
    if result.is_err() {
        let err_obj = result.unwrap_err();
        println!("KeyGen phase 3 checks failed. {:?}", err_obj.clone());
        Err(err_obj)
    } else {
        Ok(())
    }
}

macro_rules! write_input {
    ($json_file: expr, $index: expr, $stage: expr, $op: expr, $json: expr) => {{
        if var_os("WRITE_FILE").is_some() {
            let json_file = $json_file;
            let index = $index;
            let stage = $stage;
            let op = $op;
            let json = $json;
            json_file
                .write_all(format!("Input {} stage {} index {}\n", op, stage, index).as_bytes())
                .unwrap();
            json_file
                .write_all(format!("{}\n", json).as_bytes())
                .unwrap();
        }
    }};
}
macro_rules! write_output {
    ($json_file: expr, $index: expr, $stage: expr, $op: expr, $json: expr) => {{
        if var_os("WRITE_FILE").is_some() {
            let json_file = $json_file;
            let index = $index;
            let stage = $stage;
            let op = $op;
            let json = $json;
            json_file
                .write_all(format!("Output {} stage {} index {}\n", op, stage, index).as_bytes())
                .unwrap();
            json_file
                .write_all(format!("{}\n", json).as_bytes())
                .unwrap();
        }
    }};
}
/*fn write_input!(json_file: &mut File, index: u16, stage: usize, op: &String, json: String) {
    if should_write_file {
        json_file
            .write_all(format!("Input {} stage {} index {}\n", op, stage, index).as_bytes())
            .unwrap();
        json_file
            .write_all(format!("{}\n", json).as_bytes())
            .unwrap();
    }
}

fn write_output!(json_file: &mut File, index: u16, stage: usize, op: &String, json: String) {
    let should_write_file = if var_os("WRITE_FILE").is_some() {
        true
    } else {
        false
    };
    if should_write_file {
        json_file
            .write_all(format!("Output {} stage {} index {}\n", op, stage, index).as_bytes())
            .unwrap();
        json_file
            .write_all(format!("{}\n", json).as_bytes())
            .unwrap();
    }
}*/
// The Distributed key generation protocol can work with a broadcast channel.
// All the messages are exchanged p2p.
// On the contrary, the key generation process can be orchestrated as below.
// All the participants do some work on each stage and return some data.
// This data needs to be filtered/collated and sent back as an input to the next stage.
// This test helper is just a demonstration of the same.
//
pub fn keygen_orchestrator(params: Parameters) -> Result<KeyPairResult, ErrorType> {
    let op = "keygen".to_string();
    let should_write_file = if var_os("WRITE_FILE").is_some() {
        true
    } else {
        false
    };
    let mut json_file;
    if should_write_file {
        json_file = std::fs::File::create("keygen.txt").unwrap();
    }
    //
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. party_keys.u_i
    // 2. party_keys.dk
    let mut party_keys_vec_l = vec![];
    // Nothing private in the commitment values.
    let mut bc1_vec_l = vec![];
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. decommitment values in KeyGenDecommitMessage1 need to be encrypted until they are sent
    let mut decom_vec_l = vec![];
    // Nothing private in the below vector.
    let mut h1_h2_N_tilde_vec_l = vec![];
    for i in 0..params.share_count {
        let input = KeyGenStage1Input { index: i as usize };
        write_input!(
            &mut json_file,
            i,
            1,
            &op,
            serde_json::to_string_pretty(&input).unwrap()
        );
        let res = keygen_stage1(&input);
        write_output!(
            &mut json_file,
            i,
            1,
            &op,
            serde_json::to_string_pretty(&res).unwrap()
        );
        party_keys_vec_l.push(res.party_keys_l);
        bc1_vec_l.push(res.bc_com1_l);
        decom_vec_l.push(res.decom1_l);
        h1_h2_N_tilde_vec_l.push(res.h1_h2_N_tilde_l);
    }
    let mut vss_scheme_vec_l = vec![];
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. secret_shares_vec_l[i] -
    //    party.
    let mut secret_shares_vec_l = vec![];
    let mut index_vec = vec![];
    for i in 0..params.share_count {
        let input = KeyGenStage2Input {
            index: i as usize,
            params_s: params.clone(),
            party_keys_s: party_keys_vec_l.clone(),
            bc1_vec_s: bc1_vec_l.clone(),
            decom1_vec_s: decom_vec_l.clone(),
        };
        write_input!(
            &mut json_file,
            i,
            2,
            &op,
            serde_json::to_string_pretty(&input).unwrap()
        );
        let result_check = keygen_stage2(&input);
        if let Err(err) = result_check {
            return Err(err);
        }
        let res = result_check.unwrap();
        write_output!(
            &mut json_file,
            i,
            2,
            &op,
            serde_json::to_string_pretty(&res).unwrap(),
        );
        vss_scheme_vec_l.push(res.vss_scheme_s);
        secret_shares_vec_l.push(res.secret_shares_s);
        index_vec.push(res.index_s);
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
    let y_vec = (0..params.share_count)
        .map(|i| decom_vec_l[i as usize].y_i)
        .collect::<Vec<GE>>();
    for index in 0..params.share_count {
        let input = KeyGenStage3Input {
            party_keys_s: party_keys_vec_l[index as usize].clone(),
            vss_scheme_vec_s: vss_scheme_vec_l.clone(),
            secret_shares_vec_s: party_shares[index as usize].clone(),
            y_vec_s: y_vec.clone(),
            params_s: params.clone(),
            index_s: index as usize,
            index_vec_s: index_vec.clone(),
        };
        write_input!(
            &mut json_file,
            index,
            3,
            &op,
            serde_json::to_string_pretty(&input).unwrap(),
        );
        let result_check = keygen_stage3(&input);
        if let Err(err) = result_check {
            return Err(err);
        }
        let result = result_check.unwrap();
        write_output!(
            &mut json_file,
            index,
            3,
            &op,
            serde_json::to_string_pretty(&result).unwrap(),
        );
        shared_keys_vec_l.push(result.shared_keys_s);
        dlog_proof_vec_l.push(result.dlog_proof_s);
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
    let input_stage4 = KeyGenStage4Input {
        params_s: params.clone(),
        dlog_proof_vec_s: dlog_proof_vec_l.clone(),
        y_vec_s: y_vec.clone(),
    };

    for index in 0..params.share_count {
        write_input!(
            &mut json_file,
            index,
            4,
            &op,
            serde_json::to_string_pretty(&input_stage4).unwrap(),
        );
        keygen_stage4(&input_stage4)?;
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
pub struct SignStage2Input {
    pub m_a_vec: Vec<(MessageA, BigInt)>,
    pub gamma_i: FE,
    pub w_i: FE,
    pub ek_vec: Vec<EncryptionKey>,
    pub index: usize,
    pub l_ttag: usize,
    pub l_s: Vec<usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage2Result {
    pub gamma_i_vec: Vec<(MessageB, FE, BigInt, BigInt)>,
    pub w_i_vec: Vec<(MessageB, FE, BigInt, BigInt)>,
}
// This API will carry our the MtA for gamma_i MtAwc(Check happens later in stage3) for w_i
// This is basically a P2P between a participant and all it's peers.
pub fn sign_stage2(input: &SignStage2Input) -> Result<SignStage2Result, ErrorType> {
    let mut res_gamma_i = vec![];
    let mut res_w_i = vec![];
    for j in 0..input.l_ttag - 1 {
        let ind = if j < input.index { j } else { j + 1 };
        let (m_b_gamma, beta_gamma, beta_randomness, beta_tag) = MessageB::b(
            &input.gamma_i,
            &input.ek_vec[input.l_s[ind]],
            input.m_a_vec[ind].0.clone(),
        );
        res_gamma_i.push((m_b_gamma, beta_gamma, beta_randomness, beta_tag));
        let (m_b_w, beta_wi, beta_randomness, beta_tag) = MessageB::b(
            &input.w_i,
            &input.ek_vec[input.l_s[ind]],
            input.m_a_vec[ind].0.clone(),
        );
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage3Input {
    pub dk_s: DecryptionKey,
    pub k_i_s: FE,
    pub m_b_gamma_s: Vec<MessageB>,
    pub m_b_w_s: Vec<MessageB>,
    pub g_w_i_s: Vec<GE>,
    pub index_s: usize,
    pub ttag_s: usize,
}
pub fn sign_stage3(
    input: &SignStage3Input,
    /*    dk: &DecryptionKey,
    k_i: &FE,
    m_b_gamma: &[MessageB],
    m_b_w: &[MessageB],
    g_w_i: &[GE],
    index: usize,
    s_ttag: usize,*/
) -> Result<SignStage3Result, Error> {
    let mut res_alpha_vec_gamma = vec![];
    let mut res_alpha_vec_w = vec![];
    for i in 0..input.ttag_s - 1 {
        let ind = if i < input.index_s { i } else { i + 1 };
        let res = input.m_b_gamma_s[i].verify_proofs_get_alpha(&input.dk_s, &input.k_i_s)?;
        res_alpha_vec_gamma.push(res);
        let res = input.m_b_w_s[i].verify_proofs_get_alpha(&input.dk_s, &input.k_i_s)?;
        if input.g_w_i_s[ind] != input.m_b_w_s[i].b_proof.pk {
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
pub struct SignStage4Result {
    delta_i: FE,
    sigma_i: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignStage4Input {
    pub alpha_vec_s: Vec<FE>,
    pub beta_vec_s: Vec<FE>,
    pub miu_vec_s: Vec<FE>,
    pub ni_vec_s: Vec<FE>,
    pub sign_keys_s: SignKeys,
}
pub fn sign_stage4(
    input: &SignStage4Input, /*    alpha_vec: &[FE],
                             beta_vec: &[FE],
                             miu_vec: &[FE],
                             ni_vec: &[FE],
                             sign_keys: &SignKeys,
                             */
) -> Result<SignStage4Result, ErrorType> {
    Ok(SignStage4Result {
        delta_i: input
            .sign_keys_s
            .phase2_delta_i(&input.alpha_vec_s[..], &input.beta_vec_s[..]),
        sigma_i: input
            .sign_keys_s
            .phase2_sigma_i(&input.miu_vec_s[..], &input.ni_vec_s[..]),
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
    for j in 0..input.s.len() - 1 {
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
    for _ in 0..input.s.len() {
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

pub fn orchestrate_sign(
    s: &[usize],
    bytes_to_sign: &[u8],
    keypair_result: &KeyPairResult,
) -> Result<(), ErrorType> {
    let should_write_file = if var_os("WRITE_FILE").is_some() {
        true
    } else {
        false
    };

    let op = "sign".to_string();
    let mut json_file;
    if should_write_file {
        json_file = std::fs::File::create("sign.txt").unwrap();
        json_file
            .write_all(
                format!(
                    "Keypair information\n{}\n",
                    serde_json::to_string_pretty(keypair_result).unwrap()
                )
                .as_bytes(),
            )
            .unwrap();
    }
    // ttag = is the number of signers involved in the protocol.
    let ttag = s.len();
    //
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. private_vec[i].u_i
    // 2. private_vec[i].x_i
    // 3. private_vec[i].dk
    let mut private_vec = vec![];
    //
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. sign_keys_vec[i].w_i
    // 2. sign_keys_vec[i].k_i
    // 3. sign_keys_vec[i].gamma_i
    let mut sign_keys_vec = vec![];
    let mut bc1_vec = vec![];
    //
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. decom1_vec[i].blind_factor
    let mut decom1_vec = vec![];
    let mut m_a_vec: Vec<(MessageA, BigInt)> = vec![];
    (0..ttag).map(|i| i).for_each(|i| {
        let input = SignStage1Input {
            vss_scheme: keypair_result.vss_scheme.clone(),
            index: s[i],
            s_l: s.to_vec(),
            party_keys: keypair_result.party_keys_vec[s[i]].clone(),
            shared_keys: keypair_result.shared_keys_vec[s[i]].clone(),
            ek: keypair_result.party_keys_vec[s[i]].ek.clone(),
        };
        write_input!(
            &mut json_file,
            i as u16,
            1,
            &op,
            serde_json::to_string_pretty(&input).unwrap(),
        );
        let res_stage1 = sign_stage1(&input);
        write_output!(
            &mut json_file,
            i as u16,
            1,
            &op,
            serde_json::to_string_pretty(&res_stage1).unwrap(),
        );

        private_vec.push(res_stage1.party_private);
        sign_keys_vec.push(res_stage1.sign_keys);
        bc1_vec.push(res_stage1.bc1);
        decom1_vec.push(res_stage1.decom1);
        m_a_vec.push(res_stage1.m_a);
    });
    println!("Stage1 done");

    let gamma_i_vec = (0..ttag)
        .map(|i| sign_keys_vec[i].gamma_i)
        .collect::<Vec<FE>>();
    let w_i_vec = (0..ttag).map(|i| sign_keys_vec[i].w_i).collect::<Vec<FE>>();

    let mut res_stage2_vec: Vec<SignStage2Result> = vec![];
    for i in 0..ttag {
        let input = SignStage2Input {
            m_a_vec: m_a_vec.clone(),
            gamma_i: gamma_i_vec[i].clone(),
            w_i: w_i_vec[i].clone(),
            ek_vec: keypair_result.e_vec.clone(),
            index: i,
            l_ttag: ttag,
            l_s: s.to_vec(),
        };
        write_input!(
            &mut json_file,
            i as u16,
            2,
            &op,
            serde_json::to_string_pretty(&input).unwrap(),
        );
        let res = sign_stage2(&input)?;
        write_output!(
            &mut json_file,
            i as u16,
            2,
            &op,
            serde_json::to_string_pretty(&res).unwrap(),
        );
        res_stage2_vec.push(res);
    }
    println!("Stage2 done");
    // All these values should already be encrypted as they come from the stage2 response above.
    // All the values m_b_gamma_vec_all[i][..].c need to be private to party i.
    let mut m_b_gamma_vec_all = vec![vec![]; ttag];
    // All these values should already be encrypted as they come from the stage2 response above.
    // All the values m_b_w_vec_all[i][..].c need to be private to party i.
    let mut m_b_w_vec_all = vec![vec![]; ttag];
    for i in 0..ttag {
        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            m_b_gamma_vec_all[ind].push(res_stage2_vec[i].gamma_i_vec[j].0.clone());
            m_b_w_vec_all[ind].push(res_stage2_vec[i].w_i_vec[j].0.clone());
        }
    }

    let mut res_stage3_vec: Vec<SignStage3Result> = vec![];
    let g_wi_vec: Vec<GE> = (0..ttag).map(|a| sign_keys_vec[a].g_w_i).collect();
    for i in 0..ttag {
        let input = SignStage3Input {
            dk_s: keypair_result.party_keys_vec[s[i]].dk.clone(),
            k_i_s: sign_keys_vec[i].k_i.clone(),
            m_b_gamma_s: m_b_gamma_vec_all[i].clone(),
            m_b_w_s: m_b_w_vec_all[i].clone(),
            index_s: i,
            ttag_s: ttag,
            g_w_i_s: g_wi_vec.clone(),
        };
        write_input!(
            &mut json_file,
            i as u16,
            3,
            &op,
            serde_json::to_string_pretty(&input).unwrap(),
        );

        let res = sign_stage3(&input);
        if let Err(err) = res {
            println!("stage 3 error.{:?}", err);
            return Err(ErrorType {
                error_type: "".to_string(),
                bad_actors: vec![],
            });
        }
        write_output!(
            &mut json_file,
            i as u16,
            3,
            &op,
            serde_json::to_string_pretty(&(res.clone().unwrap())).unwrap(),
        );

        res_stage3_vec.push(res.unwrap());
    }
    println!("Stage 3 done.");

    //
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. beta_vec_all[i][..] - All these values are private to party i.
    let mut beta_vec_all = vec![vec![]; ttag];
    //
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // 1. ni_vec_all[i][..] - All these values are private to party i.
    let mut ni_vec_all = vec![vec![]; ttag];
    for i in 0..ttag {
        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            beta_vec_all[ind].push(res_stage2_vec[i].gamma_i_vec[j].1.clone());
            ni_vec_all[ind].push(res_stage2_vec[i].w_i_vec[j].1.clone());
        }
    }

    //
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // miu_vec_all[i][..] <-- all these values are private to party i. They should be encrypted at
    // the time of their generation in stage3.
    let miu_vec_all = (0..res_stage3_vec.len())
        .map(|i| {
            res_stage3_vec[i]
                .alpha_vec_w
                .iter()
                .map(|(miu, _miu_bigint)| *miu)
                .collect()
        })
        .collect::<Vec<Vec<FE>>>();
    //
    // Values to be kept private(Each value needs to be encrypted with a key only known to that
    // party):
    // alpha_vec_all[i][..] <-- all these values are private to party i. They should be encrypted at
    // the time of their generation in stage3.
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
        //
        // Values to be kept private(Each value needs to be encrypted with a key only known to that
        // party):
        // beta_vec[..] <-- all these values are private to party i. They should be encrypted at
        // the time of their generation in stage3.

        let beta_vec = (0..ttag - 1)
            .map(|j| {
                let ind1 = if j < i { j } else { j + 1 };
                let ind2 = if j < i { i - 1 } else { i };
                let beta = beta_vec_all[ind1][ind2].clone();

                beta
            })
            .collect::<Vec<FE>>();

        // prepare ni_vec of party_i:
        // Values to be kept private(Each value needs to be encrypted with a key only known to that
        // party):
        // ni_vec[..] <-- all these values are private to party i. They should be encrypted at
        // the time of their generation in stage3.
        let ni_vec = (0..ttag - 1)
            .map(|j| {
                let ind1 = if j < i { j } else { j + 1 };
                let ind2 = if j < i { i - 1 } else { i };
                ni_vec_all[ind1][ind2].clone()
            })
            .collect::<Vec<FE>>();
        let input = SignStage4Input {
            alpha_vec_s: alpha_vec_all[i].clone(),
            beta_vec_s: beta_vec,
            miu_vec_s: miu_vec_all[i].clone(),
            ni_vec_s: ni_vec,
            sign_keys_s: sign_keys_vec[i].clone(),
        };
        write_input!(
            &mut json_file,
            i as u16,
            4,
            &op,
            serde_json::to_string_pretty(&input).unwrap(),
        );

        let res = sign_stage4(&input).unwrap();
        write_output!(
            &mut json_file,
            i as u16,
            4,
            &op,
            serde_json::to_string_pretty(&res).unwrap(),
        );

        res_stage4_vec.push(res);
    }

    println!("Stage 4 done.");
    let delta_vec: Vec<FE> = res_stage4_vec.iter().map(|val| val.delta_i).collect();
    // all parties broadcast delta_i and compute delta_i ^(-1)
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    // sigma_vec should come out encrypted for each party in the stage 4 response itself.
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
        write_input!(
            &mut json_file,
            i as u16,
            5,
            &op,
            serde_json::to_string_pretty(&input).unwrap(),
        );

        let res = sign_stage5(&input)?;
        write_output!(
            &mut json_file,
            i as u16,
            5,
            &op,
            serde_json::to_string_pretty(&res).unwrap(),
        );

        result_stage5_vec.push(res);
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
        write_input!(
            &mut json_file,
            i as u16,
            6,
            &op,
            serde_json::to_string_pretty(&input).unwrap(),
        );

        let res = sign_stage6(&input)?;
        write_output!(
            &mut json_file,
            i as u16,
            6,
            &op,
            serde_json::to_string_pretty(&res).unwrap(),
        );

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
        write_input!(
            &mut json_file,
            i as u16,
            7,
            &op,
            serde_json::to_string_pretty(&input).unwrap(),
        );

        let res = sign_stage7(&input)?;
        write_input!(
            &mut json_file,
            i as u16,
            7,
            &op,
            serde_json::to_string_pretty(&res).unwrap(),
        );

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
        write_input!(
            &mut json_file,
            i as u16,
            8,
            &op,
            serde_json::to_string_pretty(&input).unwrap(),
        );

        let check_local_sig = sign_stage8(&input);
        if check_local_sig.is_err() {
            return Err(ErrorType {
                error_type: format!(" Signature error on index {}", i),
                bad_actors: vec![],
            });
        }
        let local_sig = check_local_sig.unwrap();
        write_output!(
            &mut json_file,
            i as u16,
            8,
            &op,
            serde_json::to_string_pretty(&local_sig).unwrap(),
        );

        s_vec.push(local_sig.s_i.clone());
        local_sig_vec.push(local_sig);
    }

    println!("Stage 8 done. s_vec len {}", s_vec.len());

    let res_sig = local_sig_vec[0].output_signature(&s_vec[1..]);
    if res_sig.is_err() {
        println!("error in combining sigs {:?}", res_sig.unwrap_err());
        return Err(ErrorType {
            error_type: "error in combining signatures".to_string(),
            bad_actors: vec![],
        });
    }
    let sig = res_sig.unwrap();
    check_sig(&sig.r, &sig.s, &local_sig_vec[0].m, &keypair_result.y_sum);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_sign_orchestration_all() {
        let keypairs = keygen_orchestrator(Parameters {
            share_count: 3,
            threshold: 1,
        })
        .unwrap();
        let msg: Vec<u8> = vec![44, 56, 78, 90, 100];
        let mut s: Vec<usize> = vec![0, 1, 2];
        let sign_result = orchestrate_sign(&s[..], &msg, &keypairs);
        assert!(sign_result.is_ok());

        s = vec![0, 1];
        let sign_result = orchestrate_sign(&s[..], &msg, &keypairs);
        assert!(sign_result.is_ok());

        s = vec![1, 2];
        let sign_result = orchestrate_sign(&s[..], &msg, &keypairs);
        assert!(sign_result.is_ok());

        s = vec![0, 2];
        let sign_result = orchestrate_sign(&s[..], &msg, &keypairs);
        assert!(sign_result.is_ok());
    }
    #[test]
    fn test_sign_orchestration_selected() {
        let keypairs = keygen_orchestrator(Parameters {
            share_count: 3,
            threshold: 1,
        })
        .unwrap();
        let msg: Vec<u8> = vec![44, 56, 78, 90, 100];
        let mut s: Vec<usize> = vec![0, 1];
        let sign_result = orchestrate_sign(&s[..], &msg, &keypairs);
        assert!(sign_result.is_ok());

        s = vec![1, 2];
        let sign_result = orchestrate_sign(&s[..], &msg, &keypairs);
        assert!(sign_result.is_ok());

        s = vec![0, 2];
        let sign_result = orchestrate_sign(&s[..], &msg, &keypairs);
        assert!(sign_result.is_ok());
    }
}
