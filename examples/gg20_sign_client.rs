#![allow(non_snake_case)]

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters,
    PartyPrivate, SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use multi_party_ecdsa::Error;
use paillier::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env::var_os;
use std::fs::File;
use std::io::Write;
use std::{env, fs, time};
use zk_paillier::zkproofs::DLogStatement;

mod common;
use common::{
    aes_decrypt, aes_encrypt, broadcast, check_sig, poll_for_broadcasts, poll_for_p2p, postb,
    sendp2p, Params, PartySignup, AEAD,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParamsFile {
    pub parties: String,
    pub threshold: String,
}

impl From<ParamsFile> for Parameters {
    fn from(item: ParamsFile) -> Self {
        Parameters {
            share_count: item.parties.parse::<u16>().unwrap(),
            threshold: item.threshold.parse::<u16>().unwrap(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys_s: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int_s: u16,
    pub vss_scheme_vec_s: Vec<VerifiableSS>,
    pub paillier_key_vec_s: Vec<EncryptionKey>,
    pub y_sum_s: GE,
    pub h1_h2_N_tilde_l_s: DLogStatement,
}
pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-sign".to_string();

    let res_body = postb(&client, "signupsign", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}
#[allow(clippy::cognitive_complexity)]
fn main() {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }
    let message_str = env::args().nth(3).unwrap_or_else(|| "".to_string());
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
    let keypair: PartyKeyPair = serde_json::from_str(&data).unwrap();

    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();
    let params_l: Parameters = serde_json::from_str::<ParamsFile>(
        &std::fs::read_to_string("params.json").expect("Could not read input params file"),
    )
    .unwrap()
    .into();

    //signup:
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    // round 0: collect signers IDs
    assert!(broadcast(
        &client,
        party_num_int,
        "round0",
        serde_json::to_string(&keypair.party_num_int_s).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round0",
        uuid.clone(),
    );

    let mut j = 0;
    //0 indexed vec containing ids of the signing parties.
    let mut signers_vec: Vec<usize> = Vec::new();
    for i in 1..=THRESHOLD + 1 {
        if i == party_num_int {
            signers_vec.push((keypair.party_num_int_s - 1) as usize);
        } else {
            let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push((signer_j - 1) as usize);
            j += 1;
        }
    }

    let input_stage1 = SignStage1Input {
        vss_scheme: keypair.vss_scheme_vec_s[signers_vec[(party_num_int - 1) as usize]].clone(),
        index: signers_vec[(party_num_int - 1) as usize],
        s_l: signers_vec.clone(),
        party_keys: keypair.party_keys_s.clone(),
        shared_keys: keypair.shared_keys,
    };
    let res_stage1 = sign_stage1(&input_stage1);

    // publish message A  and Commitment and then gather responses from other parties.
    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&(
            res_stage1.bc1.clone(),
            res_stage1.m_a.0.clone(),
            res_stage1.sign_keys.g_w_i
        ))
        .unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round1",
        uuid.clone(),
    );

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();
    let mut g_w_i_vec: Vec<GE> = vec![];

    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            bc1_vec.push(res_stage1.bc1.clone());
            g_w_i_vec.push(res_stage1.sign_keys.g_w_i.clone());
        } else {
            let (bc1_j, m_a_party_j, g_w_i): (SignBroadcastPhase1, MessageA, GE) =
                serde_json::from_str(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            g_w_i_vec.push(g_w_i);
            m_a_vec.push(m_a_party_j);

            j += 1;
        }
    }
    let mut enc_key: Vec<Vec<u8>> = vec![];
    let mut j = 0;
    for (i, k) in signers_vec.iter().enumerate() {
        if *k != (party_num_int - 1) as usize {
            enc_key.push(BigInt::to_vec(
                &(g_w_i_vec[*k as usize] * res_stage1.sign_keys.w_i.clone())
                    .x_coor()
                    .unwrap(),
            ));
        }
    }
    assert_eq!(signers_vec.len() - 1, enc_key.len());
    assert_eq!(signers_vec.len(), bc1_vec.len());

    let input_stage2 = SignStage2Input {
        m_a_vec: m_a_vec.clone(),
        gamma_i: res_stage1.sign_keys.gamma_i.clone(),
        w_i: res_stage1.sign_keys.w_i.clone(),
        ek_vec: keypair.paillier_key_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        l_ttag: signers_vec.len() as usize,
        l_s: signers_vec.clone(),
    };

    let res_stage2 = sign_stage2(&input_stage2).expect("sign stage2 failed.");
    // Send out MessageB, beta, ni to other signers so that they can calculate there alpha values.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let beta_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage2.gamma_i_vec[j].1.to_big_int()),
            );
            let ni_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage2.w_i_vec[j].1.to_big_int()),
            );

            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&(
                    res_stage2.gamma_i_vec[j].0.clone(),
                    beta_enc,
                    res_stage2.w_i_vec[j].clone(),
                    ni_enc,
                ))
                .unwrap(),
                uuid.clone()
            )
            .is_ok());
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round2",
        uuid.clone(),
    );

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    // Will store the decrypted values received from other parties.
    let mut beta_vec: Vec<FE> = vec![];
    let mut ni_vec: Vec<FE> = vec![];

    for i in 0..THRESHOLD {
        let (l_mb_gamma, l_enc_beta, l_mb_w, l_enc_ni): (MessageB, AEAD, MessageB, AEAD) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(l_mb_gamma);
        m_b_w_rec_vec.push(l_mb_w);
        let out = aes_decrypt(&enc_key[i as usize], l_enc_beta);
        let bn = BigInt::from(&out[..]);
        beta_vec.push(ECScalar::from(&bn));

        let out = aes_decrypt(&enc_key[i as usize], l_enc_ni);
        let bn = BigInt::from(&out[..]);
        ni_vec.push(ECScalar::from(&bn));
    }

    let input_stage3 = SignStage3Input {
        dk_s: keypair.party_keys_s.dk.clone(),
        k_i_s: res_stage1.sign_keys.k_i.clone(),
        m_b_gamma_s: m_b_gamma_rec_vec.clone(),
        m_b_w_s: m_b_w_rec_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        ttag_s: signers_vec.len(),
        g_w_i_s: g_w_i_vec.clone(),
    };

    let res_stage3 = sign_stage3(&input_stage3).expect("Sign stage 3 failed.");
    // Send out alpha, miu to other signers.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let alpha_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage3.alpha_vec_gamma[j].to_big_int()),
            );
            let miu_enc: AEAD = aes_encrypt(
                &enc_key[j],
                &BigInt::to_vec(&res_stage3.alpha_vec_w[j].to_big_int()),
            );

            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&(alpha_enc, miu_enc)).unwrap(),
                uuid.clone()
            )
            .is_ok());
        }
    }

    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round3",
        uuid.clone(),
    );
    let mut alpha_vec = vec![];
    let mut miu_vec = vec![];
    for i in 0..THRESHOLD {
        let (l_alpha_enc, l_miu_enc): (AEAD, AEAD) =
            serde_json::from_str(&round3_ans_vec[i as usize]).unwrap();
        let out = aes_decrypt(&enc_key[i as usize], l_alpha_enc);
        let bn = BigInt::from(&out[..]);
        alpha_vec.push(ECScalar::from(&bn));

        let out = aes_decrypt(&enc_key[i as usize], l_miu_enc);
        let bn = BigInt::from(&out[..]);
        miu_vec.push(ECScalar::from(&bn));
    }

    let input_stage4 = SignStage4Input {
        alpha_vec_s: alpha_vec.clone(),
        beta_vec_s: beta_vec.clone(),
        miu_vec_s: miu_vec.clone(),
        ni_vec_s: ni_vec.clone(),
        sign_keys_s: res_stage1.sign_keys.clone(),
    };
    let res_stage4 = sign_stage4(&input_stage4).expect("Sign Stage4 failed.");
    //broadcast decommitment from stage1 and delta_i
    assert!(broadcast(
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&(res_stage1.decom1.clone(), res_stage4.delta_i,)).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round4",
        uuid.clone(),
    );
    let mut delta_i_vec = vec![];
    let mut decom1_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            delta_i_vec.push(res_stage4.delta_i.clone());
            decom1_vec.push(res_stage1.decom1.clone());
        } else {
            let (decom_l, delta_l): (SignDecommitPhase1, FE) =
                serde_json::from_str(&round4_ans_vec[j]).unwrap();
            delta_i_vec.push(delta_l);
            decom1_vec.push(decom_l);
            j += 1;
        }
    }

    let delta_inv_l = SignKeys::phase3_reconstruct_delta(&delta_i_vec);
    let input_stage5 = SignStage5Input {
        m_b_gamma_vec: m_b_gamma_rec_vec.clone(),
        delta_inv: delta_inv_l.clone(),
        decom_vec1: decom1_vec.clone(),
        bc1_vec: bc1_vec.clone(),
        index: (party_num_int - 1) as usize,
        sign_keys: res_stage1.sign_keys.clone(),
        s_ttag: signers_vec.len(),
    };
    let res_stage5 = sign_stage5(&input_stage5).expect("Sign Stage 5 failed.");
    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&(
            res_stage5.R_dash.clone(),
            res_stage5.R.clone(),
            keypair.h1_h2_N_tilde_l_s.clone(),
        ))
        .unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round5",
        uuid.clone(),
    );
    let mut R_vec = vec![];
    let mut R_dash_vec = vec![];
    let mut h1_h2_N_tilde_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            R_vec.push(res_stage5.R.clone());
            R_dash_vec.push(res_stage5.R_dash.clone());
            h1_h2_N_tilde_vec.push(keypair.h1_h2_N_tilde_l_s.clone());
        } else {
            let (R_dash, R, randomness, h1_h2_N_tilde): (GE, GE, BigInt, DLogStatement) =
                serde_json::from_str(&round5_ans_vec[j]).unwrap();
            R_vec.push(R);
            R_dash_vec.push(R_dash);
            h1_h2_N_tilde_vec.push(h1_h2_N_tilde);
            j += 1;
        }
    }
    let input_stage6 = SignStage6Input {
        R_dash: res_stage5.R_dash.clone(),
        R: res_stage5.R.clone(),
        m_a: res_stage1.m_a.0.clone(),
        e_k: keypair.paillier_key_vec_s[signers_vec[(party_num_int - 1) as usize] as usize].clone(),
        k_i: res_stage1.sign_keys.k_i.clone(),
        randomness: res_stage1.m_a.1.clone(),
        party_keys: keypair.party_keys_s.clone(),
        h1_h2_N_tilde_vec: h1_h2_N_tilde_vec.clone(),
        index: (party_num_int - 1) as usize,
        s: signers_vec.clone(),
    };
    let res_stage6 = sign_stage6(&input_stage6).expect("stage6 sign failed.");
    /*    assert!(broadcast(
        &client,
        party_num_int,
        "round6",
        serde_json::to_string(&(res_stage6.phase5_proof.clone(),)).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round6_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round6",
        uuid.clone(),
    );
    let mut phase5_proof_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            phase5_proof_vec.push(res_stage6.phase5_proof.clone());
        } else {
            let (phase5_proof): (Vec<PDLwSlackProof>) =
                serde_json::from_str(&round6_ans_vec[j]).unwrap();
            phase5_proof_vec.push(phase5_proof);
            j += 1;
        }
    }
    */
    let input_stage7 = SignStage7Input {
        phase5_proof_vec: res_stage6.phase5_proof.clone(),
        R_dash: res_stage5.R_dash.clone(),
        R: res_stage5.R.clone(),
        m_a: res_stage1.m_a.0.clone(),
        ek: keypair.party_keys_s.ek.clone(),
        h1_h2_N_tilde_vec: h1_h2_N_tilde_vec.clone(),
        s: signers_vec.clone(),
        index: (party_num_int - 1) as usize,
    };
    let res_stage7 = sign_stage7(&input_stage7).expect("sign stage 7 failed.");
    println!("Stage 7 done.");
    let message_bn = HSha256::create_hash(&[&BigInt::from(message)]);
    let input_stage8 = SignStage8Input {
        R_dash_vec: R_dash_vec.clone(),
        sign_key: res_stage1.sign_keys.clone(),
        message_bn: message_bn.clone(),
        R: res_stage5.R.clone(),
        sigma: res_stage4.sigma_i.clone(),
        ysum: keypair.y_sum_s.clone(),
    };
    let res_stage8 = sign_stage8(&input_stage8).expect("Sign stage 8 failed.");
}