#![allow(non_snake_case)]
extern crate crypto;
extern crate curv;
/// to run:
/// 1: go to rocket_server -> cargo run
/// 2: cargo run from PARTIES number of terminals
extern crate multi_party_ecdsa;
extern crate paillier;
extern crate reqwest;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::mta::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
use paillier::*;
use reqwest::Client;
use std::env;
use std::fs;
use std::time::Duration;
use std::{thread, time};

#[derive(Hash, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct TupleKey {
    pub first: String,
    pub second: String,
    pub third: String,
    pub fourth: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u32,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: TupleKey,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: TupleKey,
    pub value: String,
}
#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

fn main() {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }
    let message_str = env::args().nth(3).unwrap_or("".to_string());
    let message = message_str.as_bytes();
    let client = Client::new();
    // delay:
    let delay = time::Duration::from_millis(25);
    // read key file
    let data = fs::read_to_string(env::args().nth(2).unwrap())
        .expect("Unable to load keys, did you run keygen first? ");
    let (party_keys, shared_keys, party_id, vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u32,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        GE,
    ) = serde_json::from_str(&data).unwrap();

    //read parameters:
    let data = fs::read_to_string("params")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let THRESHOLD: u32 = params.threshold.parse::<u32>().unwrap();

    //////////////////////////////////////////////////////////////////////////////
    //signup:
    let party_i_signup_result = signup(&client);
    assert!(party_i_signup_result.is_ok());
    let party_i_signup = party_i_signup_result.unwrap();
    println!("{:?}", party_i_signup.clone());
    let party_num_int = party_i_signup.number.clone();
    let uuid = party_i_signup.uuid;

    //////////////////////////////////////////////////////////////////////////////
    // round 0: collect signers IDs
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round0",
        serde_json::to_string(&party_id).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round0",
        uuid.clone(),
    );

    let mut j = 0;
    let mut signers_vec: Vec<usize> = Vec::new();
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            signers_vec.push((party_id - 1) as usize);
        } else {
            let signer_j: u32 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push((signer_j - 1) as usize);
            j = j + 1;
        }
    }
    // signers_vec.sort();

    let sign_keys = SignKeys::create(
        &shared_keys,
        &vss_scheme_vec[signers_vec[(party_num_int - 1) as usize]],
        signers_vec[(party_num_int - 1) as usize],
        &signers_vec,
    );

    let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
    //////////////////////////////////////////////////////////////////////////////
    let (com, decommit) = sign_keys.phase1_broadcast();
    let m_a_k = MessageA::a(&sign_keys.k_i, &party_keys.ek);
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round1",
        serde_json::to_string(&(com.clone(), m_a_k.clone())).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round1",
        uuid.clone(),
    );

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            bc1_vec.push(com.clone());
        //   m_a_vec.push(m_a_k.clone());
        } else {
            //     if signers_vec.contains(&(i as usize)) {
            let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                serde_json::from_str(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            m_a_vec.push(m_a_party_j);

            j = j + 1;
            //       }
        }
    }
    assert_eq!(signers_vec.len(), bc1_vec.len());

    //////////////////////////////////////////////////////////////////////////////
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<FE> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<FE> = Vec::new();
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let (m_b_gamma, beta_gamma) = MessageB::b(
                &sign_keys.gamma_i,
                &paillier_key_vector[signers_vec[(i - 1) as usize]],
                m_a_vec[j].clone(),
            );
            let (m_b_w, beta_wi) = MessageB::b(
                &sign_keys.w_i,
                &paillier_key_vector[signers_vec[(i - 1) as usize]],
                m_a_vec[j].clone(),
            );
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j = j + 1;
        }
    }

    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            assert!(sendp2p(
                &client,
                party_num_int.clone(),
                i.clone(),
                "round2",
                serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))
                    .unwrap(),
                uuid.clone()
            )
            .is_ok());
            j = j + 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round2",
        uuid.clone(),
    );

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..THRESHOLD {
        //  if signers_vec.contains(&(i as usize)) {
        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);
        //     }
    }

    let mut alpha_vec: Vec<FE> = Vec::new();
    let mut miu_vec: Vec<FE> = Vec::new();

    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let m_b = m_b_gamma_rec_vec[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma);
            miu_vec.push(alpha_ij_wi);
            let g_w_i = Keys::update_commitments_to_xi(
                &xi_com_vec[signers_vec[(i - 1) as usize]],
                &vss_scheme_vec[signers_vec[(i - 1) as usize]],
                signers_vec[(i - 1) as usize],
                &signers_vec,
            );
            assert_eq!(m_b.b_proof.pk.clone(), g_w_i);
            j = j + 1;
        }
    }
    //////////////////////////////////////////////////////////////////////////////
    let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round3",
        serde_json::to_string(&delta_i).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round3_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round3",
        uuid.clone(),
    );
    let mut delta_vec: Vec<FE> = Vec::new();
    format_vec_from_reads(
        &round3_ans_vec,
        party_num_int.clone() as usize,
        delta_i,
        &mut delta_vec,
    );
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    //////////////////////////////////////////////////////////////////////////////
    // decommit to gamma_i
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round4",
        serde_json::to_string(&decommit).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round4",
        uuid.clone(),
    );

    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
    format_vec_from_reads(
        &round4_ans_vec,
        party_num_int.clone() as usize,
        decommit,
        &mut decommit_vec,
    );
    let decomm_i = decommit_vec.remove((party_num_int - 1) as usize);
    bc1_vec.remove((party_num_int - 1) as usize);
    let b_proof_vec = (0..m_b_gamma_rec_vec.len())
        .map(|i| &m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof>>();
    let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
        .expect("bad gamma_i decommit");

    // adding local g_gamma_i
    let R = R + decomm_i.g_gamma_i * &delta_inv;

    let message_bn = HSha256::create_hash(&vec![&BigInt::from(message)]);

    let local_sig =
        LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof) = local_sig.phase5a_broadcast_5b_zkproof();

    //phase (5A)  broadcast commit
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round5",
        serde_json::to_string(&phase5_com).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round5",
        uuid.clone(),
    );

    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
    format_vec_from_reads(
        &round5_ans_vec,
        party_num_int.clone() as usize,
        phase5_com,
        &mut commit5a_vec,
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round6",
        serde_json::to_string(&(phase_5a_decom.clone(), helgamal_proof.clone())).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round6_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round6",
        uuid.clone(),
    );

    let mut decommit5a_and_elgamal_vec: Vec<(Phase5ADecom1, HomoELGamalProof)> = Vec::new();
    format_vec_from_reads(
        &round6_ans_vec,
        party_num_int.clone() as usize,
        (phase_5a_decom.clone(), helgamal_proof.clone()),
        &mut decommit5a_and_elgamal_vec,
    );
    let decommit5a_and_elgamal_vec_includes_i = decommit5a_and_elgamal_vec.clone();
    decommit5a_and_elgamal_vec.remove((party_num_int - 1) as usize);
    commit5a_vec.remove((party_num_int - 1) as usize);
    let phase_5a_decomm_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof>>();
    let (phase5_com2, phase_5d_decom2) = local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_decom.V_i,
            &R.clone(),
        )
        .expect("error phase5");

    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round7",
        serde_json::to_string(&phase5_com2).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round7_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round7",
        uuid.clone(),
    );

    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    format_vec_from_reads(
        &round7_ans_vec,
        party_num_int.clone() as usize,
        phase5_com2,
        &mut commit5c_vec,
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round8",
        serde_json::to_string(&phase_5d_decom2).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round8_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round8",
        uuid.clone(),
    );

    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    format_vec_from_reads(
        &round8_ans_vec,
        party_num_int.clone() as usize,
        phase_5d_decom2.clone(),
        &mut decommit5d_vec,
    );

    let phase_5a_decomm_vec_includes_i = (0..THRESHOLD + 1)
        .map(|i| decommit5a_and_elgamal_vec_includes_i[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = local_sig
        .phase5d(
            &decommit5d_vec,
            &commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round9",
        serde_json::to_string(&s_i).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round9_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int.clone(),
        THRESHOLD + 1,
        delay.clone(),
        "round9",
        uuid.clone(),
    );

    let mut s_i_vec: Vec<FE> = Vec::new();
    format_vec_from_reads(
        &round9_ans_vec,
        party_num_int.clone() as usize,
        s_i,
        &mut s_i_vec,
    );

    s_i_vec.remove((party_num_int - 1) as usize);
    let (s, r) = local_sig
        .output_signature(&s_i_vec)
        .expect("verification failed");
    println!(" \n");
    println!("party {:?} Output Signature: \n", party_num_int);
    println!("R: {:?}", r.get_element());
    println!("s: {:?} \n", s.get_element());
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a Vec<String>,
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j = j + 1;
        }
    }
}

pub fn postb<T>(client: &Client, path: &str, body: T) -> Option<String>
where
    T: serde::ser::Serialize,
{
    let addr = env::args()
        .nth(1)
        .unwrap_or("http://127.0.0.1:8001".to_string());
    let res = client
        .post(&format!("{}/{}", addr, path))
        .json(&body)
        .send();
    Some(res.unwrap().text().unwrap())
}

pub fn signup(client: &Client) -> Result<(PartySignup), ()> {
    let key = TupleKey {
        first: "signup".to_string(),
        second: "sign".to_string(),
        third: "".to_string(),
        fourth: "".to_string(),
    };

    let res_body = postb(&client, "signupsign", key).unwrap();
    let answer: Result<(PartySignup), ()> = serde_json::from_str(&res_body).unwrap();
    return answer;
}

pub fn broadcast(
    client: &Client,
    party_num: u32,
    round: &str,
    data: String,
    uuid: String,
) -> Result<(), ()> {
    let key = TupleKey {
        first: party_num.to_string(),
        second: round.to_string(),
        third: uuid,
        fourth: "".to_string(),
    };
    let entry = Entry {
        key: key.clone(),
        value: data,
    };

    let res_body = postb(&client, "set", entry).unwrap();
    let answer: Result<(), ()> = serde_json::from_str(&res_body).unwrap();
    return answer;
}

pub fn sendp2p(
    client: &Client,
    party_from: u32,
    party_to: u32,
    round: &str,
    data: String,
    uuid: String,
) -> Result<(), ()> {
    let key = TupleKey {
        first: party_from.to_string(),
        second: round.to_string(),
        third: uuid,
        fourth: party_to.to_string(),
    };
    let entry = Entry {
        key: key.clone(),
        value: data,
    };

    let res_body = postb(&client, "set", entry).unwrap();
    let answer: Result<(), ()> = serde_json::from_str(&res_body).unwrap();
    return answer;
}

pub fn poll_for_broadcasts(
    client: &Client,
    party_num: u32,
    n: u32,
    delay: Duration,
    round: &str,
    uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..n + 1 {
        if i != party_num {
            let key = TupleKey {
                first: i.to_string(),
                second: round.to_string(),
                third: uuid.clone(),
                fourth: "".to_string(),
            };
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);
                let res_body = postb(client, "get", index.clone()).unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if answer.is_ok() {
                    ans_vec.push(answer.unwrap().value);
                    println!("party {:?} {:?} read success", i, round);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub fn poll_for_p2p(
    client: &Client,
    party_num: u32,
    n: u32,
    delay: Duration,
    round: &str,
    uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..n + 1 {
        if i != party_num {
            let key = TupleKey {
                first: i.to_string(),
                second: round.to_string(),
                third: uuid.clone(),
                fourth: party_num.to_string(),
            };
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                thread::sleep(delay);
                let res_body = postb(client, "get", index.clone()).unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if answer.is_ok() {
                    ans_vec.push(answer.unwrap().value);
                    println!("party {:?} {:?} read success", i, round);
                    break;
                }
            }
        }
    }
    ans_vec
}
