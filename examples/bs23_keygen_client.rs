#![allow(non_snake_case)]

use multi_party_ecdsa::protocols::multi_party_ecdsa::bs_2023::party_i::{
    Parameters,
};
use reqwest::Client;
use std::{env, fs};

mod common;
use common::{Params, PartySignup, signup};
use common::bs23::VSS;

impl From<Params> for Parameters {
    fn from(item: Params) -> Self {
        Parameters {
            share_count: item.parties.parse::<u16>().unwrap(),
            threshold: item.threshold.parse::<u16>().unwrap(),
        }
    }
}

fn main() {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }

    let params: Parameters = serde_json::from_str::<Params>(
        &std::fs::read_to_string("params.json").expect("Could not read input params file"),
    )
    .unwrap()
    .into();

    let client = Client::new();
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    let party_key_pair = VSS(&client, party_num_int, &uuid, &params);
    fs::write(
        &env::args().nth(2).unwrap(),
        serde_json::to_string(&party_key_pair).unwrap(),
    )
    .expect("Unable to save !");
    fs::write(
        &env::args().nth(3).unwrap(),
        serde_json::to_string(&party_key_pair.shared_keys.y).unwrap(),
    )
    .expect("Unable to save !");
}
