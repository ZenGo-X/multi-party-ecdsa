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
extern crate hex;
extern crate serde_json;
#[macro_use]
extern crate time_test;

use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::ProveDLog;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::CommWitness;
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PSSFirstMessage {
    pub k_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

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
    time_test!();
    if env::args().nth(5).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(4).is_none() {
        panic!("too few arguments")
    }

    let message_str = env::args().nth(3).unwrap_or("".to_string());
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
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

    let private = PartyPrivate::set_private(party_keys.clone(), shared_keys.clone());

    let mut sign_keys = SignKeys::create(
        &private,
        &vss_scheme_vec[signers_vec[(party_num_int - 1) as usize]],
        signers_vec[(party_num_int - 1) as usize],
        &signers_vec,
    );
    let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
    let mut g_w_j: Vec<GE> = vec![GE::generator(); (THRESHOLD) as usize];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            g_w_j[j] = Keys::update_commitments_to_xi(
                &xi_com_vec[signers_vec[(i - 1) as usize]],
                &vss_scheme_vec[signers_vec[(i - 1) as usize]],
                signers_vec[(i - 1) as usize],
                &signers_vec,
            );
            j = j + 1;
        }
    }
    ///////////################################ REFRESH ########################

    let mut refresh_string;
    let mut d_fe: FE;
    let refresh_once = match fs::read_to_string(env::args().nth(4).unwrap()) {
        Ok(x) => {
            let mut k = 0;
            while k < 50 {
                //change according to num of repetitions
                refresh_string = x.clone();
                let (R, epoch, d, K, z): (GE, BigInt, BigInt, GE, FE) =
                    serde_json::from_str(&refresh_string).unwrap();
                let zG = GE::generator() * &z;
                let e = HSha256::create_hash(&vec![
                    &R.bytes_compressed_to_big_int(),
                    &K.bytes_compressed_to_big_int(),
                    &d,
                    &epoch,
                ]);

                let e_fe: FE = ECScalar::from(&e);
                let e_pk = &shared_keys.y * &e_fe;
                let e_pk_K = e_pk + &K;
                assert_eq!(zG, e_pk_K);
                d_fe = ECScalar::from(&d);
                // "ind" is the party index (one base) as it was in keygen. (signers_vec is
                // ordering indices based on time of joining, party_num_int is the number of the party
                // in the signing protocol)
                let ind = signers_vec[(party_num_int.clone() - 1) as usize] + 1;
                let ind_fe: FE = ECScalar::from(&BigInt::from(ind as i32));

                let db = d_fe * &ind_fe;
                let li =
                    vss_scheme_vec[ind as usize - 1].map_share_to_new_params(ind - 1, &signers_vec);

                let db_new_param = db * &li;
                let sk_i_tag = sign_keys.w_i + &db_new_param;
                let sk_i_tag_G = GE::generator() * &sk_i_tag;
                sign_keys.w_i = sk_i_tag;
                sign_keys.g_w_i = sk_i_tag_G;

                // g_w_j[0] is the counter party local public key: here is how we update it.

                let ind = signers_vec.iter().fold(0, |acc, x| acc + x + 1) - ind;
                let refresh_point =
                    GE::generator() * &d_fe * &ECScalar::from(&BigInt::from(ind as i32));
                let refresh_point_new_param = Keys::update_commitments_to_xi(
                    &refresh_point,
                    &vss_scheme_vec[(ind - 1) as usize],
                    (ind - 1) as usize,
                    &signers_vec,
                );
                g_w_j[0] = g_w_j[0] + refresh_point_new_param;
                k = k + 1;
            }
            true
        }
        Err(_) => false,
    };

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

    let j = 0;
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

            assert_eq!(m_b.b_proof.pk.clone(), g_w_j[j]);
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

    //################# PSS 2: Sample new polynomial ##############

    //phase (2i)  coin toss folded with phase (3i) common k:
    let k_i: FE = FE::new_random();
    let G_k_i = GE::generator() * &k_i;
    let d_log_proof = DLogProof::prove(&k_i);
    // we use hash based commitment
    let pk_commitment_blind_factor = BigInt::sample(256);
    let k_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
        &G_k_i.bytes_compressed_to_big_int(),
        &pk_commitment_blind_factor,
    );

    let zk_pok_blind_factor = BigInt::sample(256);
    let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
        &d_log_proof
            .pk_t_rand_commitment
            .bytes_compressed_to_big_int(),
        &zk_pok_blind_factor,
    );
    let com_witness = CommWitness {
        pk_commitment_blind_factor,
        zk_pok_blind_factor,
        public_share: G_k_i.clone(),
        d_log_proof,
    };

    let pss_first_message = PSSFirstMessage {
        k_commitment,
        zk_pok_commitment,
    };

    // use rounds 5-6-7 broadcasts to complete pss
    ////////////////////////////////

    // we assume the message is already hashed (by the signer).
    let message_bn = BigInt::from(message);
    let two = BigInt::from(2);
    let message_bn = message_bn.modulus(&two.pow(256));
    let local_sig =
        LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof) = local_sig.phase5a_broadcast_5b_zkproof();

    //phase (5A)  broadcast commit
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round5",
        serde_json::to_string(&(phase5_com.clone(), pss_first_message.clone())).unwrap(),
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

    let mut commit5a_and_pss_vec: Vec<(Phase5Com1, PSSFirstMessage)> = Vec::new();
    format_vec_from_reads(
        &round5_ans_vec,
        party_num_int.clone() as usize,
        (phase5_com, pss_first_message),
        &mut commit5a_and_pss_vec,
    );
    let mut commit5a_vec = vec![
        commit5a_and_pss_vec[0].0.clone(),
        commit5a_and_pss_vec[1].0.clone(),
    ];
    let zk_comm_vec = vec![
        commit5a_and_pss_vec[0].1.clone(),
        commit5a_and_pss_vec[1].1.clone(),
    ];

    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round6",
        serde_json::to_string(&(
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            com_witness.clone()
        ))
        .unwrap(),
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

    let mut decommit5a_and_elgamal_and_com_wit_vec: Vec<(
        Phase5ADecom1,
        HomoELGamalProof,
        CommWitness,
    )> = Vec::new();
    format_vec_from_reads(
        &round6_ans_vec,
        party_num_int.clone() as usize,
        (phase_5a_decom.clone(), helgamal_proof.clone(), com_witness),
        &mut decommit5a_and_elgamal_and_com_wit_vec,
    );
    let mut decommit5a_and_elgamal_vec = vec![
        (
            decommit5a_and_elgamal_and_com_wit_vec[0].0.clone(),
            decommit5a_and_elgamal_and_com_wit_vec[0].1.clone(),
        ),
        (
            decommit5a_and_elgamal_and_com_wit_vec[1].0.clone(),
            decommit5a_and_elgamal_and_com_wit_vec[1].1.clone(),
        ),
    ];
    let zk_decomm_vec = vec![
        decommit5a_and_elgamal_and_com_wit_vec[0].2.clone(),
        decommit5a_and_elgamal_and_com_wit_vec[1].2.clone(),
    ];

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

    //######### PSS cont #########
    // verify decom's and let d be hash of sum of k
    if signers_vec[0] == party_num_int.clone() as usize {
        let pk_commitment = &zk_comm_vec[1].k_commitment;
        let zk_pok_commitment = &zk_comm_vec[1].zk_pok_commitment;
        let zk_pok_blind_factor = &zk_decomm_vec[1].zk_pok_blind_factor;
        let public_share = &zk_decomm_vec[1].public_share;
        let pk_commitment_blind_factor = &zk_decomm_vec[1].pk_commitment_blind_factor;
        let d_log_proof = &zk_decomm_vec[1].d_log_proof;

        let mut flag = true;
        match pk_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &public_share.bytes_compressed_to_big_int(),
                &pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &d_log_proof
                    .pk_t_rand_commitment
                    .bytes_compressed_to_big_int(),
                &zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        DLogProof::verify(&d_log_proof).expect("error zk-dlog verify");
    } else {
        let pk_commitment = &zk_comm_vec[0].k_commitment;
        let zk_pok_commitment = &zk_comm_vec[0].zk_pok_commitment;
        let zk_pok_blind_factor = &zk_decomm_vec[0].zk_pok_blind_factor;
        let public_share = &zk_decomm_vec[0].public_share;
        let pk_commitment_blind_factor = &zk_decomm_vec[0].pk_commitment_blind_factor;
        let d_log_proof = &zk_decomm_vec[0].d_log_proof;

        let mut flag = true;
        match pk_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &public_share.bytes_compressed_to_big_int(),
                &pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &d_log_proof
                    .pk_t_rand_commitment
                    .bytes_compressed_to_big_int(),
                &zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        DLogProof::verify(&d_log_proof).expect("error zk-dlog verify");;
    }

    let d = HSha256::create_hash(&vec![
        &zk_decomm_vec[0].public_share.bytes_compressed_to_big_int(),
        &zk_decomm_vec[1].public_share.bytes_compressed_to_big_int(),
    ]);
    //  let d_fe: FE = ECScalar::from(&d);
    let K = &zk_decomm_vec[0].public_share + &zk_decomm_vec[1].public_share;
    //let party_num_bn : BigInt= BigInt::from(&party_num_int as i32);
    //  let party_num_fe: FE = ECScalar::from(&BigInt::from(party_num_int.clone() as i32));
    // let db = d_fe * &party_num_fe;
    // let sk_b_tag = sign_keys.w_i + &db;
    let epoch = BigInt::one();
    let e = HSha256::create_hash(&vec![
        &R.bytes_compressed_to_big_int(),
        &K.bytes_compressed_to_big_int(),
        &d,
        &epoch,
    ]);
    let e_fe: FE = ECScalar::from(&e);
    let z_b = e_fe * &sign_keys.w_i + k_i;

    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        &client,
        party_num_int.clone(),
        "round7",
        serde_json::to_string(&(phase5_com2.clone(), z_b.clone())).unwrap(),
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

    let mut commit5c_and_z_b_vec: Vec<(Phase5Com2, FE)> = Vec::new();
    format_vec_from_reads(
        &round7_ans_vec,
        party_num_int.clone() as usize,
        (phase5_com2, z_b),
        &mut commit5c_and_z_b_vec,
    );

    let commit5c_vec = vec![
        commit5c_and_z_b_vec[0].0.clone(),
        commit5c_and_z_b_vec[1].0.clone(),
    ];
    let z_b_vec = vec![
        commit5c_and_z_b_vec[0].1.clone(),
        commit5c_and_z_b_vec[1].1.clone(),
    ];

    // this part will fail for more than 2 parties. TODO: add explicit check for threshold
    let z_b_counter;
    //  let l_counter;
    let K_c;
    // let x_i;
    //  let counter_index;
    let ind = signers_vec[(party_num_int.clone() - 1) as usize] + 1;
    if signers_vec[0] == (ind - 1) as usize {
        z_b_counter = z_b_vec[1];
        //     x_i = xi_com_vec[1];
        //     counter_index = signers_vec[1];
        //   l_counter = vss_scheme_vec[counter_index.clone()]
        //       .map_share_to_new_params(counter_index, &signers_vec[..]);
        K_c = zk_decomm_vec[1].public_share;
    } else {
        z_b_counter = z_b_vec[0];
        //     x_i = xi_com_vec[0];
        //     counter_index = signers_vec[0];
        //   l_counter = vss_scheme_vec[counter_index.clone()]
        //       .map_share_to_new_params(counter_index, &signers_vec[..]);
        K_c = zk_decomm_vec[0].public_share;
    }

    let z_b_c_G = GE::generator() * &z_b_counter;
    // let mut pk_c = x_i * l_counter;
    if refresh_once {
        //    let ind = counter_index + 1;
        //pk_c = pk_c + GE::generator() * &d_fe * &ECScalar::from(&BigInt::from(ind as i32));
    }
    let pk_c = g_w_j[0];
    let e_pk_c_plus_k_c = pk_c * &e_fe + K_c;

    assert_eq!(z_b_c_G, e_pk_c_plus_k_c);

    let z = z_b_vec[0] + z_b_vec[1];

    let keygen_json =
        serde_json::to_string(&(R.clone(), epoch.clone(), d.clone(), K.clone(), z.clone()))
            .unwrap();

    fs::write(env::args().nth(4).unwrap(), keygen_json).expect("Unable to save refresh!");

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
    let sig = local_sig
        .output_signature(&s_i_vec)
        .expect("verification failed");
    println!(" \n");
    println!("party {:?} Output Signature: \n", party_num_int);
    println!("R: {:?}", sig.r.get_element());
    println!("s: {:?} \n", sig.s.get_element());
    let sign_json = serde_json::to_string(&(
        "r",
        (BigInt::from(&(sig.r.get_element())[..])).to_str_radix(16),
        "s",
        (BigInt::from(&(sig.s.get_element())[..])).to_str_radix(16),
    ))
    .unwrap();

    fs::write("signature".to_string(), sign_json).expect("Unable to save !");
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
    let retries = 3;
    let retry_delay = time::Duration::from_millis(250);
    for _i in 1..retries {
        let res = client
            .post(&format!("{}/{}", addr, path))
            .json(&body)
            .send();
        if res.is_ok() {
            return Some(res.unwrap().text().unwrap());
        }
        thread::sleep(retry_delay);
    }
    None
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
