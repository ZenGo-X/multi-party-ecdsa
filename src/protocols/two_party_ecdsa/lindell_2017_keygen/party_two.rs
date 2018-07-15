/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

use cryptography_utils::EC;
use cryptography_utils::PK;
use cryptography_utils::SK;
use super::party_one;
use cryptography_utils::elliptic::curves::traits::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
#[derive(Debug)]
pub struct FirstMsg1 {
    d_log_proof : DLogProof,
    pub public_share: PK,
    secret_share : SK
}

impl FirstMsg1 {
    pub fn create(ec_context: &EC) -> DLogProof {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context);

        DLogProof::prove(&ec_context, &pk, &sk)
    }
}

#[derive(Debug)]
pub struct SecondMsg {
    pub d_log_proof_result : Result<(), ProofError>
}

impl SecondMsg{
    pub fn verify_commitments_and_dlog_proof(ec_context: &EC, party_one_first_messsage: &party_one::FirstMsg,  party_one_second_messsage: &party_one::SecondMsg) -> SecondMsg {
        let mut flag = true;
        match party_one_first_messsage.pk_commitment == HashCommitment::create_commitment_with_user_defined_randomness(
            &party_one_second_messsage.public_share.to_point().x, &party_one_second_messsage.pk_commitment_blind_factor)
            {false => flag = false};
        match party_one_first_messsage.zk_pok_commitment == HashCommitment::create_commitment_with_user_defined_randomness(
            &party_one_second_messsage.d_log_proof.pk_t_rand_commitment.to_point().x, &party_one_second_messsage.zk_pok_blind_factor)
            {false => flag = false};
        SecondMsg {
            d_log_proof_result: DLogProof::verify(ec_context, &party_one_second_messsage.d_log_proof)
        }
    }

}