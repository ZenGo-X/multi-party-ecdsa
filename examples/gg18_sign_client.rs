#![allow(non_snake_case)]

use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2, SharedKeys, SignatureRecid, SignBroadcastPhase1, SignDecommitPhase1, SignKeys};
use multi_party_ecdsa::utilities::mta::*;
use sha2::Sha256;

use paillier::EncryptionKey;
use std::{env, fs, time};
use curv::elliptic::curves::Curve;

mod common;
use common::{
    check_sig, Params,
};

mod party_client;
use crate::party_client::{ClientPurpose, PartyClient};

#[derive(Clone, Debug)]
struct StoreFileData {
    party_keys: Keys,
    shared_keys: SharedKeys,
    party_id:u16,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    paillier_key_vector: Vec<EncryptionKey>,
    public_key: Point<Secp256k1>
}

#[derive(Clone, Debug)]
struct Round1Result {
    sign_keys: SignKeys,
    bc1_vec: Vec<SignBroadcastPhase1>,
    xi_com_vec: Vec<Point<Secp256k1>>,
    decommit: SignDecommitPhase1,
    m_b_w_send_vec: Vec<MessageB>,
    m_b_gamma_send_vec: Vec<MessageB>,
    beta_vec: Vec<Scalar<Secp256k1>>,
    ni_vec: Vec<Scalar<Secp256k1>>
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
    let address = env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8001".to_string());
    // delay:
    let delay = time::Duration::from_millis(25);
    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();

    let client = PartyClient::new(
        ClientPurpose::Sign,
        Secp256k1::CURVE_NAME,
        address,
        delay,
        params
    );

    // read key file
    let store_file_data: StoreFileData = read_store_file();

    // round 0: collect signers IDs
    let signers_vec: Vec<u16> = client.exchange_data(THRESHOLD+1, "round0", store_file_data.party_id - 1);

    let round1_result = run_round1(
        client.clone(),
        store_file_data.clone(),
        signers_vec.clone(),
        THRESHOLD
    );

    let (alpha_vec, miu_vec, m_b_gamma_rec_vec) = run_round2(
        client.clone(),
        THRESHOLD,
        round1_result.clone(),
        signers_vec.clone(),
        store_file_data.clone(),

    );

    //////////////////////////////////////////////////////////////////////////////
    let delta_inv = run_round3(
        client.clone(),
        round1_result.clone(),
        alpha_vec,
        THRESHOLD
    );

    //////////////////////////////////////////////////////////////////////////////
    // decommit to gamma_i
    let R = run_round4(
        client.clone(),
        THRESHOLD,
        round1_result.clone(),
        delta_inv,
        m_b_gamma_rec_vec
    );

    // we assume the message is already hashed (by the signer).
    let message_bn = BigInt::from_bytes(message);

    let sig = run_round5(
        client.clone(),
        THRESHOLD,
        message_bn.clone(),
        round1_result.clone(),
        store_file_data.clone(),
        R,
        miu_vec
    );

    // check sig against secp256k1
    check_sig(&sig.r, &sig.s, &message_bn, &store_file_data.public_key);

    print_and_save_signature(sig, client.party_number.clone());
}

fn read_store_file() -> StoreFileData {
    let data = fs::read_to_string(env::args().nth(2).unwrap())
        .expect("Unable to load keys, did you run keygen first? ");
    let (party_keys, shared_keys, party_id, vss_scheme_vec, paillier_key_vector, public_key): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Secp256k1>>,
        Vec<EncryptionKey>,
        Point<Secp256k1>,
    ) = serde_json::from_str(&data).unwrap();

    StoreFileData {
        party_keys,
        shared_keys,
        party_id,
        vss_scheme_vec,
        paillier_key_vector,
        public_key
    }
}


fn run_round1(client: PartyClient, store_file_data: StoreFileData, signers_vec:Vec<u16>, THRESHOLD: u16) -> Round1Result {
    let party_keys = store_file_data.party_keys;
    let shared_keys = store_file_data.shared_keys;
    let vss_scheme_vec = store_file_data.vss_scheme_vec;
    let paillier_key_vector = store_file_data.paillier_key_vector;

    let party_num_int = client.party_number;

    let private = PartyPrivate::set_private(party_keys.clone(), shared_keys);

    let sign_keys = SignKeys::create(
        &private,
        &vss_scheme_vec[usize::from(signers_vec[usize::from(party_num_int - 1)])],
        signers_vec[usize::from(party_num_int - 1)],
        &signers_vec,
    );

    let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
    //////////////////////////////////////////////////////////////////////////////
    let (com, decommit) = sign_keys.phase1_broadcast();
    let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &party_keys.ek, &[]);
    let round1_ans_vector = client.exchange_data(
        THRESHOLD + 1,
        "round1",
        (com.clone(), m_a_k.clone())
    );

    let mut j = 0;
    let bc1_vec: Vec<SignBroadcastPhase1> = round1_ans_vector
        .iter()
        .map(|x1| x1.0.clone())
        .collect();

    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            //     if signers_vec.contains(&(i as usize)) {
            let (_bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) = round1_ans_vector[(i-1) as usize].clone();
            m_a_vec.push(m_a_party_j);
            j = j + 1;
            //       }
        }
    }
    assert_eq!(signers_vec.len(), bc1_vec.len());

    //////////////////////////////////////////////////////////////////////////////
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &sign_keys.gamma_i,
                &paillier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
                m_a_vec[j].clone(),
                &[],
            )
                .unwrap();
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &sign_keys.w_i,
                &paillier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
                m_a_vec[j].clone(),
                &[],
            )
                .unwrap();
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j += 1;
        }
    }

    Round1Result {
        sign_keys,
        bc1_vec,
        xi_com_vec,
        decommit,
        m_b_w_send_vec,
        m_b_gamma_send_vec,
        beta_vec,
        ni_vec
    }
}


fn run_round2(client: PartyClient, THRESHOLD: u16, round1_result: Round1Result, signers_vec: Vec<u16>, store_file_data: StoreFileData) ->
    (Vec<Scalar<Secp256k1>>, Vec<Scalar<Secp256k1>>, Vec<MessageB>)
{

    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != client.party_number {
            assert!(client.sendp2p(
                i,
                "round2",
                serde_json::to_string(&(round1_result.m_b_gamma_send_vec[j].clone(), round1_result.m_b_w_send_vec[j].clone()))
                    .unwrap(),
            )
                .is_ok());
            j += 1;
        }
    }

    let round2_ans_vec = client.poll_for_p2p(
        THRESHOLD + 1,
        "round2",
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

    let mut alpha_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    let mut miu_vec: Vec<Scalar<Secp256k1>> = Vec::new();

    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != client.party_number {
            let m_b = m_b_gamma_rec_vec[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&store_file_data.party_keys.dk, &round1_result.sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&store_file_data.party_keys.dk, &round1_result.sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &round1_result.xi_com_vec[usize::from(signers_vec[usize::from(i - 1)])],
                &store_file_data.vss_scheme_vec[usize::from(signers_vec[usize::from(i - 1)])],
                signers_vec[usize::from(i - 1)],
                &signers_vec,
            );
            assert_eq!(m_b.b_proof.pk, g_w_i);
            j += 1;
        }
    }

    (alpha_vec, miu_vec, m_b_gamma_rec_vec)
}

fn run_round3(client: PartyClient, round1_result: Round1Result, alpha_vec: Vec<Scalar<Secp256k1>>, THRESHOLD: u16) -> Scalar<Secp256k1> {
    let delta_i = round1_result.sign_keys.phase2_delta_i(&alpha_vec, &round1_result.beta_vec);

    let delta_vec: Vec<Scalar<Secp256k1>> = client.exchange_data(THRESHOLD+1, "round3", delta_i);

    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    delta_inv
}

fn run_round4(client: PartyClient, THRESHOLD: u16, round1_result: Round1Result, delta_inv: Scalar<Secp256k1>, m_b_gamma_rec_vec: Vec<MessageB>) -> Point<Secp256k1>
{
    let mut decommit_vec: Vec<SignDecommitPhase1> = client.exchange_data(
        THRESHOLD+1,
        "round4",
        round1_result.decommit
    );

    let decomm_i = decommit_vec.remove(usize::from(client.party_number - 1));
    let mut bc1_vec = round1_result.bc1_vec;
    bc1_vec.remove(usize::from(client.party_number - 1));
    let b_proof_vec = (0..m_b_gamma_rec_vec.len())
        .map(|i| &m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
    let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
        .expect("bad gamma_i decommit");

    // adding local g_gamma_i
    let R = R + decomm_i.g_gamma_i * delta_inv;

    R
}


fn run_round5(
    client: PartyClient,
    THRESHOLD: u16,
    message_bn: BigInt,
    round1_result: Round1Result,
    store_file_data: StoreFileData,
    R: Point<Secp256k1>,
    miu_vec: Vec<Scalar<Secp256k1>>
) -> SignatureRecid
{

    let party_index = usize::from(client.party_number - 1);
    let sigma = round1_result.sign_keys.phase2_sigma_i(&miu_vec, &round1_result.ni_vec);

    let local_sig =
        LocalSignature::phase5_local_sig(&round1_result.sign_keys.k_i, &message_bn, &R, &sigma, &store_file_data.public_key);

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
        local_sig.phase5a_broadcast_5b_zkproof();

    //phase (5A)  broadcast commit
    let mut commit5a_vec: Vec<Phase5Com1> = client.exchange_data(
        THRESHOLD+1,
        "round5",
        phase5_com
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    )> = client.exchange_data(
        THRESHOLD+1,
        "round6",
        (
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone()
        )
    );

    let decommit5a_and_elgamal_and_dlog_vec_includes_i =
        decommit5a_and_elgamal_and_dlog_vec.clone();
    decommit5a_and_elgamal_and_dlog_vec.remove(party_index);
    commit5a_vec.remove(party_index);
    let phase_5a_decomm_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof<Secp256k1, Sha256>>>();
    let phase_5a_dlog_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
        .collect::<Vec<DLogProof<Secp256k1, Sha256>>>();
    let (phase5_com2, phase_5d_decom2) = local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_dlog_vec,
            &phase_5a_decom.V_i,
            &R,
        )
        .expect("error phase5");

    //////////////////////////////////////////////////////////////////////////////
    let commit5c_vec: Vec<Phase5Com2> = client.exchange_data(
        THRESHOLD + 1,
        "round7",
        phase5_com2
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    let decommit5d_vec: Vec<Phase5DDecom2> = client.exchange_data(
        THRESHOLD + 1,
        "round8",
        phase_5d_decom2
    );

    let phase_5a_decomm_vec_includes_i = (0..=THRESHOLD)
        .map(|i| {
            decommit5a_and_elgamal_and_dlog_vec_includes_i[i as usize]
                .0
                .clone()
        })
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = local_sig
        .phase5d(
            &decommit5d_vec,
            &commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    //////////////////////////////////////////////////////////////////////////////
    let mut s_i_vec: Vec<Scalar<Secp256k1>> = client.exchange_data(
        THRESHOLD + 1,
        "round9",
        s_i
    );

    s_i_vec.remove(party_index);
    let sig = local_sig
        .output_signature(&s_i_vec)
        .expect("verification failed");

    sig
}

fn print_and_save_signature(sig: SignatureRecid, party_num_int: u16) {

    println!("party {:?} Output Signature: \n", party_num_int);
    println!("R: {:?}", sig.r);
    println!("s: {:?} \n", sig.s);
    println!("recid: {:?} \n", sig.recid.clone());

    let sign_json = serde_json::to_string(&(
        "r",
        BigInt::from_bytes(sig.r.to_bytes().as_ref()).to_str_radix(16),
        "s",
        BigInt::from_bytes(sig.s.to_bytes().as_ref()).to_str_radix(16),
    ))
        .unwrap();

    fs::write("signature".to_string(), sign_json).expect("Unable to save !");
}