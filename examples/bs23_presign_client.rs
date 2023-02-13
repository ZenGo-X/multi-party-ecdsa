#![allow(non_snake_case)]

use curv::arithmetic::BigInt;
use curv::arithmetic::traits::*;
use curv::elliptic::curves::secp256_k1::{FE, GE, SK};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::cryptographic_primitives::hashing::{
    hash_sha256::HSha256,
    traits::Hash,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::bs_2023::orchestrate::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::bs_2023::party_i::{
    Parameters, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, PartyPrivate,
    SignatureRecid, verify,
};
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
use reqwest::Client;
use std::{env, fs, time};
use serde::{Deserialize, Serialize};

mod common;
use common::{broadcast, poll_for_broadcasts, poll_for_p2p, sendp2p, signup, Params, PartySignup};
use common::bs23::{Presignature, LocalSecret, localSS, PartyKeyPair, VSS};

static DELAY: std::time::Duration = time::Duration::from_millis(25);

impl From<Params> for Parameters {
    fn from(item: Params) -> Self {
        Parameters {
            share_count: item.parties.parse::<u16>().unwrap(),
            threshold: item.threshold.parse::<u16>().unwrap(),
        }
    }
}

#[allow(clippy::cognitive_complexity)]
fn main() {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }

    // params
    let params: Parameters = serde_json::from_str::<Params>(
        &std::fs::read_to_string("params.json").expect("Could not read input params file"),
    )
    .unwrap()
    .into();

    // read key file
    let data = fs::read_to_string(env::args().nth(2).unwrap())
        .expect("Unable to load keys, did you run keygen first? ");
    let keypair: PartyKeyPair = serde_json::from_str(&data).unwrap();

    // signup
    let client = Client::new();
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    // decentralized signing secret
    let sig_secret = VSS(&client, party_num_int, &uuid, &params);
    // modified MTA
    let res_phase2 = phase2(&client, party_num_int, uuid.clone(), keypair.clone(), sig_secret.clone(), &params);
    // Computing R
    let res_phase3 = phase3(&client, party_num_int, uuid.clone(), keypair.clone(), sig_secret.clone(), &params);

    let presig = Presignature{
        party_num_int: party_num_int,
        sig_secret: sig_secret.clone(),
        R: res_phase3.R,
        u: res_phase2.u.set_private(),
        v: res_phase2.v.set_private(),
        a_ii: res_phase2.a_ii,
        a_ij_vec: res_phase2.a_ij_vec,
        ysum: res_phase3.ysum,
        vss_scheme: keypair.vss_scheme_vec_s.clone()
    };
    
    // UNSAFE: Testing locally the presig result
    //test_presig(&client, party_num_int, uuid.clone(), keypair.clone(), sig_secret.clone(), &params, &presig);

    fs::write(
        &env::args().nth(3).unwrap(),
        serde_json::to_string(&presig).unwrap(),
    )
    .expect("Unable to save !");
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase2Result {
    pub party_num_int: u16,
    pub u: LocalSecret,
    pub v: LocalSecret,
    pub a_ii: SK,
    pub a_ij_vec: Vec<Vec<SK>>,
}
fn phase2(client: &Client, party_num_int: u16, uuid: String, keypair: PartyKeyPair, 
        sig_secret: PartyKeyPair, params: &Parameters) -> Phase2Result {
    // params
    let PARTY_NUM = params.share_count;
    let _THRESHOLD = params.threshold;

    // Init local secrets
    let u: LocalSecret = localSS(&params);
    let v: LocalSecret = localSS(&params);

    // m_a: encryption of k_i
    let ek = keypair.party_keys_s.ek.clone();
    let m_a = MessageA::a(&sig_secret.shared_keys.x_i, &ek);

    // Collecting messageA
    assert!(broadcast(
        &client,
        party_num_int,
        "P2 round1",
        serde_json::to_string(&m_a.0.clone()).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTY_NUM,
        DELAY,
        "P2 round1",
        uuid.clone(),
    );

    let mut j = 0;
    let mut m_a_vec: Vec<MessageA> = Vec::new();
    for i in 1..PARTY_NUM + 1 {
        if i != party_num_int {
            let m_a_party_j: MessageA = serde_json::from_str(&round1_ans_vec[j as usize]).unwrap();
            m_a_vec.push(m_a_party_j);
            j += 1;
        } else {
            m_a_vec.push(m_a.0.clone());
        }
    }

    // Compiling and sending messageB
    let ek_vec = keypair.paillier_key_vec_s.clone();
    let mut m_b_vec: Vec<MessageB> = Vec::new();
    for i in 1..PARTY_NUM + 1 {
        let (m_b, _beta_randomness, _beta_tag) = MessageB::b_with_predefined_beta(
            &keypair.shared_keys.x_i,                  // x_i
            &ek_vec[(i-1) as usize],                    // client's ek_vec  is included
            m_a_vec[(i-1) as usize].clone(),            // client's m_a     is included
            &u.secret_shares[(i-1) as usize],           // beta_ij = -u_ij
        );
        m_b_vec.push(m_b.clone());

        if i != party_num_int {
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "P2 round2",
                serde_json::to_string(&m_b.clone()).unwrap(),
                uuid.clone()
            )
            .is_ok());
        }
    }
    let round2_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        PARTY_NUM,
        DELAY,
        "P2 round2",
        uuid.clone(),
    );

    let mut j = 0;
    let mut m_b_rec_vec: Vec<MessageB> = Vec::new();
    for i in 1..PARTY_NUM + 1 {
        if i != party_num_int {
            let l_mb: MessageB = serde_json::from_str(&round2_ans_vec[j as usize]).unwrap();
            m_b_rec_vec.push(l_mb);
            j += 1;
        } else {
            m_b_rec_vec.push(m_b_vec[(i-1) as usize].clone());
        }
    }

    // Decrypting messageB
    let mut a_ii = FE::zero();
    let mut a_ij_vec: Vec<SK> = vec![];
    for i in 1..PARTY_NUM + 1 {
        let alpha = m_b_rec_vec[(i-1) as usize].verify_proofs_get_alpha(
            &keypair.party_keys_s.dk.clone(),
            &sig_secret.shared_keys.x_i.clone()
        ).expect("Presign phase 2 failed.");

        if i != party_num_int {
            a_ij_vec.push(alpha.0.sub(&v.secret_shares[(i-1) as usize].get_element()).get_element());
        } else {
            a_ii = alpha.0.sub(&v.secret_shares[(i-1) as usize].get_element());
            a_ij_vec.push(FE::zero().get_element());
        }
    }

    // Sharing a_ij
    assert!(broadcast(
        &client,
        party_num_int,
        "P2 round3",
        serde_json::to_string(&a_ij_vec).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round3_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTY_NUM,
        DELAY,
        "P2 round3",
        uuid.clone(),
    );
    // println!("Client {:?}: {:?}", party_num_int, round3_ans_vec);

    let mut j = 0;
    let mut res_vec = Vec::new();
    for i in 1..PARTY_NUM + 1 {
        let round3_ans: Vec<SK>;
        if i != party_num_int {
            round3_ans = serde_json::from_str(&round3_ans_vec[j as usize]).unwrap();
            j += 1;
        } else {
            round3_ans = a_ij_vec.clone();
        }
        res_vec.push(round3_ans);

        // // Unnecessary Serialization
        // let mut a_ij_ans_vec: Vec<FE> = Vec::new();
        // for ans in round3_ans {
        //     let mut ans_fe: FE = FE::zero();
        //     ans_fe.set_element(ans);
        //     a_ij_ans_vec.push(ans_fe);
        // }
        // res_vec.push(a_ij_ans_vec);
    }

    Phase2Result{
        party_num_int: party_num_int,
        u: u,
        v: v,
        a_ii: a_ii.get_element(),
        a_ij_vec: res_vec,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase3Result {
    pub R: GE,
    pub ysum: GE,
}
fn phase3(client: &Client, party_num_int: u16, uuid: String, keypair: PartyKeyPair, 
        sig_secret: PartyKeyPair, params: &Parameters) -> Phase3Result {
    // params
    let THRESHOLD = params.threshold;
    let PARTY_NUM = params.share_count;

    // collect signers IDs
    assert!(broadcast(
        &client,
        party_num_int,
        "P3 round0",
        serde_json::to_string(&keypair.party_num_int_s).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        DELAY,
        "P3 round0",
        uuid.clone(),
    );

    let presig_vec = 
        if round0_ans_vec.len() > THRESHOLD.into() {
            assert!(broadcast(
                &client,
                party_num_int,
                "P3 round6",
                "".to_string(),
                uuid.clone()
            )
            .is_ok());
            poll_for_broadcasts(
                &client,
                party_num_int,
                PARTY_NUM,
                DELAY,
                "P3 round6",
                uuid.clone(),
            )
        }else{
            let res_stage6 = computingR(&client, party_num_int, uuid.clone(), keypair.clone(), 
                sig_secret.clone(), round0_ans_vec, THRESHOLD);

            let res = Phase3Result{
                R: res_stage6.R,
                ysum: res_stage6.ysum,
            };
            assert!(broadcast(
                &client,
                party_num_int,
                "P3 round6",
                serde_json::to_string(&res).unwrap(),
                uuid.clone()
            )
            .is_ok());
            poll_for_broadcasts(
                &client,
                party_num_int,
                PARTY_NUM,
                DELAY,
                "P3 round6",
                uuid.clone(),
            )
        };


    // agreeing on an answer
    let mut prev: String = "".to_string();
    for ans in presig_vec {
        if !(ans == "".to_string()) {
            if !(prev == "".to_string()) {
                assert!(prev == ans);
            };
            prev = ans.clone();
        };
    };
    let res_phase3: Phase3Result = serde_json::from_str(&prev).unwrap();
    res_phase3
}

fn computingR(client: &Client, party_num_int: u16, uuid: String, keypair: PartyKeyPair, 
        sig_secret: PartyKeyPair, round0_ans_vec: Vec<String>, THRESHOLD: u16) -> SignStage6Result {
    // indexed vec containing ids of the signing parties.
    let mut j = 0;
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
        sig_secret_private: PartyPrivate::set_private(sig_secret.party_keys_s.clone(), sig_secret.shared_keys.clone()),
    };
    let res_stage1 = sign_stage1(&input_stage1);
    // publish message A  and Commitment and then gather responses from other parties.
    assert!(broadcast(
        &client,
        party_num_int,
        "P3 round1",
        serde_json::to_string(&(
            res_stage1.bc1.clone(),
            res_stage1.m_a.0.clone()
        ))
        .unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        DELAY,
        "P3 round1",
        uuid.clone(),
    );

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            bc1_vec.push(res_stage1.bc1.clone());
            m_a_vec.push(res_stage1.m_a.0.clone());
        } else {
            let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                serde_json::from_str(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            m_a_vec.push(m_a_party_j);
            j += 1;
        }
    }
    assert_eq!(signers_vec.len(), bc1_vec.len());

    let input_stage2 = SignStage2Input {
        m_a_vec: m_a_vec.clone(),
        gamma_i: res_stage1.sign_keys.gamma_i.clone(),
        ek_vec: keypair.paillier_key_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        l_ttag: signers_vec.len() as usize,
        l_s: signers_vec.clone(),
    };

    let mut beta_vec: Vec<FE> = vec![];
    let res_stage2 = sign_stage2(&input_stage2).expect("sign stage2 failed.");
    // Send out MessageB, beta, ni to other signers so that they can calculate their alpha values.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            // private values and they should never be sent out.
            beta_vec.push(res_stage2.gamma_i_vec[j].1);
            // Below two are the C_b messages on page 11 https://eprint.iacr.org/2020/540.pdf
            // paillier encrypted values and are thus safe to send as is.
            let c_b_messageb_gammai = res_stage2.gamma_i_vec[j].0.clone();

            // If this client were implementing blame(Identifiable abort) then this message should have been broadcast.
            // For the current implementation p2p send is also fine.
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "P3 round2",
                serde_json::to_string(&c_b_messageb_gammai).unwrap(),
                uuid.clone()
            )
            .is_ok());

            j += 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        THRESHOLD + 1,
        DELAY,
        "P3 round2",
        uuid.clone(),
    );

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..THRESHOLD {
        let l_mb_gamma: MessageB =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(l_mb_gamma);
    }

    let input_stage3 = SignStage3Input {
        dk_s: keypair.party_keys_s.dk.clone(),
        k_i_s: res_stage1.sign_keys.k_i.clone(),
        m_b_gamma_s: m_b_gamma_rec_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        ttag_s: signers_vec.len(),
    };

    let res_stage3 = sign_stage3(&input_stage3).expect("Sign stage 3 failed.");
    let mut alpha_vec = vec![];
    // Send out alpha, miu to other signers.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            alpha_vec.push(res_stage3.alpha_vec_gamma[j]);
            j += 1;
        }
    }

    let input_stage4 = SignStage4Input {
        alpha_vec_s: alpha_vec.clone(),
        beta_vec_s: beta_vec.clone(),
        sign_keys_s: res_stage1.sign_keys.clone(),
    };
    let res_stage4 = sign_stage4(&input_stage4).expect("Sign Stage4 failed.");
    //broadcast decommitment from stage1 and delta_i
    assert!(broadcast(
        &client,
        party_num_int,
        "P3 round4",
        serde_json::to_string(&(res_stage1.decom1.clone(), res_stage4.delta_i,)).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        DELAY,
        "P3 round4",
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
        "P3 round5",
        serde_json::to_string(&(res_stage5.R_dash.clone(), res_stage5.R.clone(),)).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        DELAY,
        "P3 round5",
        uuid.clone(),
    );
    let mut R_vec = vec![];
    let mut R_dash_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            R_vec.push(res_stage5.R.clone());
            R_dash_vec.push(res_stage5.R_dash.clone());
        } else {
            let (R_dash, R): (GE, GE) = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            R_vec.push(R);
            R_dash_vec.push(R_dash);
            j += 1;
        }
    }

    let input_stage6 = SignStage6Input {
        R_dash_vec: R_dash_vec.clone(),
        R: res_stage5.R.clone(),
        m_a: res_stage1.m_a.0.clone(),
        e_k: keypair.paillier_key_vec_s[signers_vec[(party_num_int - 1) as usize] as usize].clone(),
        k_i: res_stage1.sign_keys.k_i.clone(),
        randomness: res_stage1.m_a.1.clone(),
        party_keys: keypair.party_keys_s.clone(),
        h1_h2_N_tilde_vec: keypair.h1_h2_N_tilde_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        s: signers_vec.clone(),
        ysum: keypair.y_sum_s.clone(),
        sign_key: res_stage1.sign_keys.clone(),
        // message_bn: message_bn.clone(),
    };
    let res_stage6 = sign_stage6(&input_stage6).expect("Stage6 sign failed.");
    res_stage6
}

#[allow(dead_code)]
fn test_presig(client: &Client, party_num_int: u16, uuid: String, keypair: PartyKeyPair, 
        sig_secret: PartyKeyPair, params: &Parameters, presig: &Presignature) {
    // params
    let PARTY_NUM = params.share_count;
    let THRESHOLD = params.threshold;

    // test keypair
    assert!(broadcast(
        &client,
        party_num_int,
        "Test 1",
        serde_json::to_string(&keypair.shared_keys.x_i.clone()).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTY_NUM,
        DELAY,
        "Test 1",
        uuid.clone(),
    );
    let mut j = 0;
    let mut keypair_shares = vec![];
    let mut signers_vec = vec![];
    for i in 1..PARTY_NUM + 1 {
        if i < THRESHOLD + 2 {signers_vec.push((i-1) as usize)}
        if i != party_num_int {
            let x_j: FE = serde_json::from_str(&ans_vec[j as usize]).unwrap();
            keypair_shares.push(x_j);
            j += 1;
        } else {
            keypair_shares.push(keypair.shared_keys.x_i.clone());
        }
    }

    let mut x = FE::zero();
    let params = keypair.vss_scheme_vec_s[(party_num_int - 1) as usize].parameters.clone();
    for i in 1..THRESHOLD + 2 {
        let li = VerifiableSS::<GE>::map_share_to_new_params(&params, (i-1) as usize, &signers_vec);
        x = x + li * keypair_shares[(i-1) as usize];
    }
    let g: GE = ECPoint::generator();
    assert_eq!(g * x, keypair.y_sum_s);
    assert_eq!(g * x, keypair.shared_keys.y);

    // test sig secret
    assert!(broadcast(
        &client,
        party_num_int,
        "Test 2",
        serde_json::to_string(&sig_secret.shared_keys.x_i.clone()).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTY_NUM,
        DELAY,
        "Test 2",
        uuid.clone(),
    );
    let mut j = 0;
    let mut sig_secret_shares = vec![];
    for i in 1..PARTY_NUM + 1 {
        if i != party_num_int {
            let k_j: FE = serde_json::from_str(&ans_vec[j as usize]).unwrap();
            sig_secret_shares.push(k_j);
            j += 1;
        } else {
            sig_secret_shares.push(sig_secret.shared_keys.x_i.clone());
        }
    }

    let mut k = FE::zero();
    for i in 1..THRESHOLD + 2 {
        let li = VerifiableSS::<GE>::map_share_to_new_params(&params, (i-1) as usize, &signers_vec);
        k = k + li * sig_secret_shares[(i-1) as usize];
    }
    assert_eq!(g * k, sig_secret.y_sum_s);
    assert_eq!(g * k, sig_secret.shared_keys.y);

    // test u, v
    let local_u = presig.u.set_public();
    let local_v = presig.v.set_public();
    
    let mut u = FE::zero();
    let mut v = FE::zero();
    for i in 1..THRESHOLD + 2 {
        let li = VerifiableSS::<GE>::map_share_to_new_params(&params, (i-1) as usize, &signers_vec);
        u = u + li * local_u.secret_shares[(i-1) as usize];
        v = v + li * local_v.secret_shares[(i-1) as usize];
    }
    assert_eq!(local_u.x, u);
    assert_eq!(local_v.x, v);

    // test a_ij
    assert!(broadcast(
        &client,
        party_num_int,
        "Test 3", 
        serde_json::to_string(presig).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTY_NUM,
        DELAY,
        "Test 3",
        uuid.clone(),
    );
    let mut j = 0;
    let mut a_ij = FE::zero();
    let mut presig_aii_vec = vec![];
    let mut local_u_vec = vec![];
    let mut local_v_vec = vec![];
    for i in 1..PARTY_NUM + 1 {
        if i != party_num_int {
            let ans: Presignature = serde_json::from_str(&ans_vec[j as usize]).unwrap();

            a_ij.set_element(ans.a_ii.clone());
            presig_aii_vec.push(a_ij);

            local_u_vec.push(ans.u.set_public());
            local_v_vec.push(ans.v.set_public());

            j += 1;
        } else {
            a_ij.set_element(presig.a_ii.clone());
            presig_aii_vec.push(a_ij);
            
            local_u_vec.push(presig.u.set_public());
            local_v_vec.push(presig.v.set_public());
        }
    }
    let mut a = FE::zero();
    for i in 1..THRESHOLD + 2 {
        let li = VerifiableSS::<GE>::map_share_to_new_params(&params, (i-1) as usize, &signers_vec);
        for j in 1..THRESHOLD + 2 {
            let lj = VerifiableSS::<GE>::map_share_to_new_params(&params, (j-1) as usize, &signers_vec);
            if i == j {
                a = a + li * lj * presig_aii_vec[(i-1) as usize];
            } else {
                a_ij.set_element(presig.a_ij_vec[(i-1) as usize][(j-1) as usize]);
                a = a + li * lj * a_ij;
            }
        }
        a = a + li * local_u_vec[(i-1) as usize].x + li * local_v_vec[(i-1) as usize].x;
    }
    assert_eq!(a, x * k);

    // Get message
    let message_str = fs::read_to_string("bin/message")
        .expect("Unable to load message, verify file path");
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    let message_bn = HSha256::create_hash(&[&BigInt::from_bytes(message)]);
    let m_fe: FE = ECScalar::from(&message_bn);

    // Calculate signature
    let r: FE = ECScalar::from(&presig.R.x_coor().unwrap().mod_floor(&FE::q()));
    let mut s : FE = k * (m_fe + r * x);

    // Verify signature
    let s_bn = s.to_big_int();
    let ry: BigInt = presig.R.y_coor().unwrap().mod_floor(&FE::q());

    let is_ry_odd = ry.test_bit(0);
    let mut recid = if is_ry_odd { 1 } else { 0 };
    let s_tag_bn = FE::q() - &s_bn;
    if s_bn > s_tag_bn {
        s = ECScalar::from(&s_tag_bn);
        recid = recid ^ 1;
    }

    let sig = SignatureRecid { r, s, recid };
    println!("Checking signature {:?}, {:?}", r, s);
    let ver = verify(&sig, &keypair.y_sum_s, &message_bn).is_ok();
    assert!(ver);
    println!("Client {:?}: test_presig {:?}", party_num_int, ver);
}
