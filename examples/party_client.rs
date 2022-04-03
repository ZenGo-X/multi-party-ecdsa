/*
    This file contains implementation of a client for each party in MPC applications
    Copyright 2022
    Developed by:
        HRezaei (https://github.com/HRezaei)
*/
use std::{thread, time};
use std::time::Duration;
use reqwest::blocking::Client;

use crate::common::{Index, Params, PartySignup, Entry};

#[derive(Clone)]
pub struct PartyClient {
    client: Client,
    address: String,
    uuid: String,
    delay: Duration,
    pub party_number: u16,
}

pub enum ClientPurpose {
    Keygen,
    Sign
}

impl ClientPurpose {
    fn as_str(&self) -> &'static str {
        match self {
            ClientPurpose::Keygen => "keygen",
            ClientPurpose::Sign => "sign"
        }
    }
}

impl PartyClient {
    pub fn new(purpose: ClientPurpose, curve_name: &str, address: String, delay: Duration, tn_params: Params) -> Self {

        let mut instance = Self {
            client: Client::new(),
            address,
            delay,
            uuid: "".to_string(),
            party_number: 0
        };

        //Purpose is set to segregate the sessions on the manager
        let signup_path = "signup".to_owned() + &purpose.as_str();
        let (party_num_int, uuid) = match instance.signup(&signup_path, &tn_params, curve_name).unwrap() {
            PartySignup { number, uuid } => (number, uuid),
        };

        println!("number: {:?}, uuid: {:?}, curve: {:?}", party_num_int, uuid, curve_name);

        instance.uuid = uuid;
        instance.party_number = party_num_int;

        instance
    }

    pub fn signup(&self, path:&str, params: &Params, curve_name: &str) -> Result<PartySignup, ()> {
        let res_body = self.post_request(path, (params, curve_name)).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn post_request<T>(&self, path: &str, body: T) -> Option<String>
        where
            T: serde::ser::Serialize,
    {
        let address = self.address.clone();
        let retries = 3;
        let retry_delay = time::Duration::from_millis(250);
        for _i in 1..retries {
            let url = format!("{}/{}", address, path);
            let res = self.client.post(&url).json(&body).send();

            if let Ok(res) = res {
                return Some(res.text().unwrap());
            }
            thread::sleep(retry_delay);
        }
        None
    }

    pub fn broadcast(
        &self,
        round: &str,
        data: String,
    ) -> Result<(), ()> {
        let party_num: u16 = self.party_number;
        let sender_uuid: String = self.uuid.clone();
        let key = format!("{}-{}-{}", party_num, round, sender_uuid);
        let entry = Entry {
            key: key.clone(),
            value: data,
        };
        let res_body = self.post_request("set", entry).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn sendp2p(
        &self,
        party_to: u16,
        round: &str,
        data: String,
    ) -> Result<(), ()> {
        let party_from: u16 = self.party_number;
        let sender_uuid: String = self.uuid.clone();

        let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

        let entry = Entry {
            key: key.clone(),
            value: data,
        };

        let res_body = self.post_request("set", entry).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn poll_for_broadcasts(
        &self,
        n: u16,
        round: &str,
    ) -> Vec<String> {
        let party_num: u16 = self.party_number;
        let sender_uuid: String = self.uuid.clone();

        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}", i, round, sender_uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(self.delay);
                    let res_body = self.post_request("get", index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if let Ok(answer) = answer {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
            }
        }
        ans_vec
    }

    pub fn poll_for_p2p(
        &self,
        n: u16,
        round: &str,
    ) -> Vec<String> {
        let party_num: u16 = self.party_number;
        let sender_uuid: String = self.uuid.clone();

        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(self.delay);
                    let res_body = self.post_request("get", index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if let Ok(answer) = answer {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
            }
        }
        ans_vec
    }

    pub fn exchange_data<T>(&self, parties_count:u16, round: &str, data:T) -> Vec<T>
        where
            T: Clone + serde::de::DeserializeOwned + serde::Serialize,
    {
        let party_num:u16 = self.party_number;
        assert!(self.broadcast(
            &round,
            serde_json::to_string(&data).unwrap(),
        )
            .is_ok());
        let round_ans_vec = self.poll_for_broadcasts(
            parties_count,
            &round,
        );

        let json_answers = &round_ans_vec.clone();
        let mut answers: Vec<T> = Vec::new();
        PartyClient::format_vec_from_reads(
            json_answers,
            party_num as usize,
            data,
            &mut answers
        );

        answers.clone()
    }

    fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
        ans_vec: &'a [String],
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
                j += 1;
            }
        }
    }

}
