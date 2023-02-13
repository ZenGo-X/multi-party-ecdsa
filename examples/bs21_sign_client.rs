#![allow(non_snake_case)]

use curv::arithmetic::traits::Converter;
use curv::elliptic::curves::secp256_k1::{FE};
use curv::elliptic::curves::traits::*;
use curv::cryptographic_primitives::hashing::{
    hash_sha256::HSha256,
    traits::Hash,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::bs_2021::{
    orchestrate::*,
    party_i::LocalSignature,
};
use paillier::*;
use std::{env, fs};

mod common;
use common::bs21::Presignature;

#[allow(clippy::cognitive_complexity)]
fn main() {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }

    let message_str = fs::read_to_string(env::args().nth(3).unwrap())
        .expect("Unable to load message, verify file path");
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    let message_bn = HSha256::create_hash(&[&BigInt::from_bytes(message)]);

    // read presigning file
    let data = fs::read_to_string(env::args().nth(1).unwrap())
    .expect("Unable to load presigning file, did you run keygen & presign first? ");
    let presig: Presignature = serde_json::from_str(&data).unwrap();

    let mut a_ii: FE = FE::zero();
    a_ii.set_element(presig.a_ii.clone());

    // Compiling local signature
    let local_sig_stage7 = SignStage7LocalSig {
        local_sig : LocalSignature::phase7_local_sig(
            &presig.sig_secret.shared_keys.x_i,            // k_i
            &message_bn,
            &presig.R,
            &presig.u.set_public().x,
            &presig.v.set_public().x,
            a_ii,
            &presig.ysum,
            presig.party_num_int,
            presig.vss_scheme.clone(),
        ),
        a_ij_vec: presig.a_ij_vec,
    };

    // save local sign
    fs::write(
        &env::args().nth(2).unwrap(),
        serde_json::to_string(&local_sig_stage7).unwrap(),
    )
    .expect("Unable to save !");
}
