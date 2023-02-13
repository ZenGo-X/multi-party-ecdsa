#![allow(non_snake_case)]

use curv::elliptic::curves::traits::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    LocalSignature, Parameters, Signature,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{env, fs, time};

mod common;
use common::{
    broadcast, poll_for_broadcasts, Params, 
    signup, PartySignup,
};

static DELAY: std::time::Duration = time::Duration::from_millis(25);

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

#[allow(clippy::cognitive_complexity)]
fn main() {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }

    // signup
    let client = Client::new();
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    // read presigning file
    let data = fs::read_to_string(env::args().nth(2).unwrap())
        .expect("Unable to load local signature, did you run keygen, presign & sign first? ");
    let local_sig_stage7: SignStage7LocalSig = serde_json::from_str(&data).unwrap();

    // signing
    let sign_json = compile_sig(client.clone(), party_num_int, uuid.clone(), local_sig_stage7);
    fs::write(env::args().nth(3).unwrap(), sign_json).expect("Unable to save !");
}

fn compile_sig(client: Client, party_num_int: u16, uuid: String, local_sig_stage7: SignStage7LocalSig) -> String {
    // parameters
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();

    // Broadcasting/receiving local signatures
    // (Note: this section is done using a broadcast, but localsig files can be compiled locally)
    assert!(broadcast(
        &client,
        party_num_int,
        "round7",
        serde_json::to_string(&local_sig_stage7.local_sig.clone()).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round6_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        DELAY,
        "round7",
        uuid.clone(),
    );

    // stage 7: compiling the signature
    let mut local_sig_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            local_sig_vec.push(local_sig_stage7.local_sig.clone());
        } else {
            let local_sig: LocalSignature = serde_json::from_str(&round6_ans_vec[j]).unwrap();
            local_sig_vec.push(local_sig.clone());
            j += 1;
        }
    }
    let input_stage7 = SignStage7Input {
        local_sig_vec: local_sig_vec.clone(),
        ysum: local_sig_stage7.local_sig.y.clone(),
    };
    
    let res_stage7 = sign_stage7(&input_stage7).expect("sign stage 7 failed");
    let sig = res_stage7.local_sig;
    println!(
        "party {:?} Output Signature: \nR: {:?}\ns: {:?} \nrecid: {:?} \n",
        party_num_int,
        sig.r.get_element(),
        sig.s.get_element(),
        sig.recid.clone()
    );

    let sign_json = serde_json::to_string(&Signature{
        r: sig.r.get_element(),
        s: sig.s.get_element(),
    })
    .unwrap();
    sign_json
}