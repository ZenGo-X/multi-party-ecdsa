/*
    Multi-party ECSDA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECSDA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

use ::BigInteger as BigInt;

use ::Point;
use ::EC;
use ::PK;
use ::SK;

const R_BYTES_SIZE : usize = 32;

use elliptic::curves::traits::*;

use arithmetic::traits::Modulo;
use arithmetic::traits::Samplable;

use cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptographic_primitives::proofs::ProofError;

use cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptographic_primitives::commitments::traits::Commitment;

use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

// TODO: remove the next line when unit test will be done
#[allow(dead_code)]
#[derive(Debug)]
pub struct FirstMsgCommitments {
    pub pk_commitment : BigInt,
    pk_commitment_blind_factor : BigInt,

    pub zk_pok_commitment : BigInt,
    zk_pok_blind_factor : BigInt,

    dLog_proof : DLogProof
}

impl FirstMsgCommitments {
    pub fn create(ec_context: &EC) -> FirstMsgCommitments {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context).to_big_uint();

        let dLog_proof = DLogProof::prove(&ec_context, &pk, &sk);

        let pk_commitment_blind_factor = BigInt::sample(R_BYTES_SIZE);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.to_point().x, &pk_commitment_blind_factor);

        let zk_pok_blind_factor = BigInt::sample(R_BYTES_SIZE);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &dLog_proof.pk_t_rand_commitment.to_point().x, &zk_pok_blind_factor);

        FirstMsgCommitments {
            pk_commitment,
            pk_commitment_blind_factor,

            zk_pok_commitment,
            zk_pok_blind_factor,

            dLog_proof
        }
    }
}

#[derive(Debug)]
pub struct SecondMsgClientProofVerification;

impl SecondMsgClientProofVerification {
    pub fn verify(ec_context: &EC, proof: &DLogProof) {
        assert!(DLogProof::verify(ec_context, proof).is_ok());
    }
}