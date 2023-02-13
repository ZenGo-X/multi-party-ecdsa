#![allow(non_snake_case)]

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::{
    hash_sha256::HSha256,
    traits::Hash,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
    orchestrate::*,
    party_i::LocalSignature,
};
use paillier::*;
use std::{env, fs};

// mod common;
// use common::Presignature;

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

    // TODO: USE NEW PRESIG 
    // read presigning file
    let data = fs::read_to_string(env::args().nth(1).unwrap())
    .expect("Unable to load presigning file, did you run keygen & presign first? ");
    let presig: SignStage6Result = serde_json::from_str(&data).unwrap();

    // Compiling local signature
    let local_sig_stage7 = SignStage7LocalSig {
        local_sig : LocalSignature::phase7_local_sig(
            &presig.k_i, 
            &message_bn,
            &presig.R,
            &presig.sigma,
            &presig.ysum,
        ),
    };

    // save local sign
    fs::write(
        &env::args().nth(2).unwrap(),
        serde_json::to_string(&local_sig_stage7).unwrap(),
    )
    .expect("Unable to save !");
}
