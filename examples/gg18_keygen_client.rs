#![allow(non_snake_case)]
/// to run:
/// 1: go to rocket_server -> cargo run
/// 2: cargo run from PARTIES number of terminals
use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenDecommitMessage1, Keys, Parameters,
};
use paillier::EncryptionKey;
use std::{env, fs, time};
use curv::elliptic::curves::Curve;

mod common;
use common::{
    aes_decrypt, aes_encrypt, Params,
    AEAD, AES_KEY_BYTES_LEN,
};

mod party_client;
use party_client::PartyClient;
use crate::party_client::ClientPurpose;

fn main() {
    if env::args().nth(3).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(2).is_none() {
        panic!("too few arguments")
    }
    let address = env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8001".to_string());

    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let PARTIES: u16 = params.parties.parse::<u16>().unwrap();
    let THRESHOLD: u16 = params.threshold.parse::<u16>().unwrap();
    // delay:
    let delay = time::Duration::from_millis(25);

    //Instantiates a party client and performs signup for the given purpose:
    let client = PartyClient::new(
        ClientPurpose::Keygen,
        Secp256k1::CURVE_NAME,
        address,
        delay,
        params
    );

    let params = Parameters {
        threshold: THRESHOLD,
        share_count: PARTIES,
    };

    let party_num_int = client.party_number;

    let party_keys = Keys::create(party_num_int);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    // send commitment to ephemeral public keys, get round 1 commitments of other parties
    let bc1_vec = client.exchange_data(
        PARTIES,
        "round1",
        bc_i
    );

    // send ephemeral public keys and check commitments correctness
    let decommit_vector: Vec<KeyGenDecommitMessage1> = client.exchange_data(PARTIES, "round2", decom_i);

    let point_vec: Vec<Point<Secp256k1>> = decommit_vector
        .iter()
        .map(|x| x.clone().y_i)
        .collect();

    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=PARTIES {
        if i != party_num_int {
            let decommit_j: KeyGenDecommitMessage1 = decommit_vector[(i-1) as usize].clone();
            let key_bn: BigInt = (decommit_j.y_i.clone() * party_keys.u_i.clone())
                .x_coord()
                .unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let public_key = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decommit_vector, &bc1_vec,
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(client.sendp2p(
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
            )
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = client.poll_for_p2p(
        PARTIES,
        "round3",
    );

    let mut j = 0;
    let mut party_shares: Vec<Scalar<Secp256k1>> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out[..]);
            let out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    // round 4: send vss commitments and collect them
    let vss_scheme_vec = client.exchange_data(
        PARTIES,
        "round4",
        vss_scheme
    );

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    // round 5: send dlog proof and collect them
    let dlog_proof_vec = client.exchange_data(
        PARTIES,
        "round5",
        dlog_proof
    );

    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    //save key to file:
    let paillier_key_vec = (0..PARTIES)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        public_key,
    ))
    .unwrap();
    fs::write(env::args().nth(2).unwrap(), keygen_json).expect("Unable to save !");
}
