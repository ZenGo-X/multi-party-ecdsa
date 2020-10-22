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
/*
 * thread_local! {

static SECRET_KEY: RefCell<Vec<u8>> = RefCell::new((0..32).map(|_| { rand::random::<u8>() }).collect());
}
impl From<Keys> for KeysE {
    fn from(item: Keys) {
        let json_str = serde_json::to_string(&item).unwrap();
        let val: Value = serde_json::from_str(&json_str).unwrap();
        let u_i_ser = val["u_i"].as_bytes();
        let dk_ser = val["dk"].as_bytes();
        KeysE {
            y_i: item.y_i,
            dk: aes_encrypt(&SECRET_KEY.with(|m| m.borrow.clone()), dk_ser),
            ek: item.ek,
            u_i: aes_encrypt(&SECRET_KEY.with(|m| m.borrow.clone()), u_i_ser),
            party_index: usize,
            N_tilde: BigInt,
            h1: BigInt,
            h2: BigInt,
            xhi: BigInt,
        }
    }
}
impl From<KeysE> for Keys {
    fn from(item: KeysE) {
        Keys {
            y_i: item.y_i,
            dk: serde_json::from_str(
                &aes_decrypt(&SECRET_KEY.with(|m| m.borrow.clone()), &item.dk).to_string(),
            )
            .unwrap(),
            ek: item.ek,
            u_i: serde_json::from_str(
                &aes_encrypt(&SECRET_KEY.with(|m| m.borrow.clone()), &item.u_i).to_string(),
            )
            .unwrap(),
            party_index: item.party_index,
            N_tilde: item.N_tilde,
            h1: item.h1,
            h2: item.h2,
            xhi: item.xhi,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysE {
    pub u_i: AEAD,
    pub y_i: GE,
    pub dk: AEAD,
    pub ek: EncryptionKey,
    pub party_index: usize,
    N_tilde: BigInt,
    h1: BigInt,
    h2: BigInt,
    xhi: BigInt,
}
*/
/*#[derive(StructOpt)]
struct Cli {
    #[structopt(default_value = "http://127.0.0.1:8001", long = "server", short = "s")]
    server: String,
    #[structopt(
        parse(from_os_str),
        default_value = "params.json",
        long = "params",
        short = "p"
    )]
    params_file: std::path::PathBuf,
    #[structopt(
        parse(from_os_str),
        default_value = "keys.json",
        long = "keys",
        short = "k"
    )]
    keys_file: std::path::PathBuf,
}*/
fn main() {
    if env::args().nth(3).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(2).is_none() {
        panic!("too few arguments")
    }

    //let args = Cli::from_args();
    let params: Parameters = serde_json::from_str::<ParamsFile>(
        &std::fs::read_to_string("params.json").expect("Could not read input params file"),
    )
    .unwrap()
    .into();

    let client = Client::new();
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    let delay = time::Duration::from_millis(200);
    let input_stage1 = KeyGenStage1Input {
        index: (party_num_int - 1) as usize,
    };
    let res_stage1: KeyGenStage1Result = keygen_stage1(&input_stage1);
    //let party_keys_e: KeysA = res_stage1.party_keys.clone().into();

    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&res_stage1.bc_com1_l).unwrap(),
        uuid.clone()
    )
    .is_ok());

    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round1",
        uuid.clone(),
    );
    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party_num_int as usize - 1, res_stage1.bc_com1_l);
    assert!(broadcast(
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&res_stage1.decom1_l).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round2",
        uuid.clone(),
    );
    let mut decom1_vec = round2_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenDecommitMessage1>(m).unwrap())
        .collect::<Vec<_>>();
    decom1_vec.insert(party_num_int as usize - 1, res_stage1.decom1_l);
    let input_stage2 = KeyGenStage2Input {
        index: (party_num_int - 1) as usize,
        params_s: params.clone(),
        party_keys_s: res_stage1.party_keys_l.clone(),
        decom1_vec_s: decom1_vec.clone(),
        bc1_vec_s: bc1_vec.clone(),
    };
    let res_stage2 = keygen_stage2(&input_stage2).expect("keygen stage 2 failed.");

    let mut point_vec: Vec<GE> = Vec::new();
    let mut enc_keys: Vec<BigInt> = Vec::new();
    for i in 1..=params.share_count {
        point_vec.push(decom1_vec[(i - 1) as usize].y_i);
        if i != party_num_int {
            enc_keys.push(
                (decom1_vec[(i - 1) as usize].y_i.clone() * res_stage1.party_keys_l.u_i)
                    .x_coor()
                    .unwrap(),
            );
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let mut j = 0;
    for (k, i) in (1..=params.share_count).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = BigInt::to_vec(&enc_keys[j]);
            let plaintext = BigInt::to_vec(&res_stage2.secret_shares_s[k].to_big_int());
            let aead_pack_i = aes_encrypt(&key_i, &plaintext);
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            )
            .is_ok());
            j += 1;
        }
    }
    // get shares from other parties.
    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round3",
        uuid.clone(),
    );
    // decrypt shares from other parties.
    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            party_shares.push(res_stage2.secret_shares_s[(i - 1) as usize]);
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = BigInt::to_vec(&enc_keys[j]);
            let out = aes_decrypt(&key_i, aead_pack);
            let out_bn = BigInt::from(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }
    assert!(broadcast(
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&res_stage2.vss_scheme_s).unwrap(),
        uuid.clone()
    )
    .is_ok());
    //get vss_scheme for others.
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round4",
        uuid.clone(),
    );

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            vss_scheme_vec.push(res_stage2.vss_scheme_s.clone());
        } else {
            let vss_scheme_j: VerifiableSS = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }
    let input_stage3 = KeyGenStage3Input {
        party_keys_s: res_stage1.party_keys_l.clone(),
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        secret_shares_vec_s: party_shares,
        y_vec_s: point_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        params_s: params.clone(),
    };
    let res_stage3 = keygen_stage3(&input_stage3).expect("stage 3 keygen failed.");
    // round 5: send dlog proof
    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&res_stage3.dlog_proof_s).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round5",
        uuid.clone(),
    );

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            dlog_proof_vec.push(res_stage3.dlog_proof_s.clone());
        } else {
            let dlog_proof_j: DLogProof = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }

    let input_stage4 = KeyGenStage4Input {
        params_s: params.clone(),
        dlog_proof_vec_s: dlog_proof_vec.clone(),
        y_vec_s: point_vec.clone(),
    };
    let res_stage4 = keygen_stage4(&input_stage4).expect("keygen stage4 failed.");
    //save key to file:
    let paillier_key_vec = (0..params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let party_key_pair = PartyKeyPair {
        party_keys_s: res_stage1.party_keys_l.clone(),
        shared_keys: res_stage3.shared_keys_s.clone(),
        party_num_int_s: party_num_int,
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        paillier_key_vec_s: paillier_key_vec,
        y_sum_s: y_sum,
    };
    fs::write(
        &env::args().nth(2).unwrap(),
        serde_json::to_string(&party_key_pair).unwrap(),
    )
    .expect("Unable to save !");
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys_s: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int_s: u16,
    pub vss_scheme_vec_s: Vec<VerifiableSS>,
    pub paillier_key_vec_s: Vec<EncryptionKey>,
    pub y_sum_s: GE,
}
pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-keygen".to_string();

    let res_body = postb(&client, "signupkeygen", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}
/*
fn main() {}
*/
