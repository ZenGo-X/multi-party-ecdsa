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

use cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptographic_primitives::commitments::traits::Commitment;

use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

use cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptographic_primitives::proofs::ProofError;

#[derive(Debug)]
pub struct FirstMsgCommitment {
    dLog_proof : DLogProof
}

impl FirstMsgCommitment {
    pub fn create(ec_context: &EC) -> DLogProof {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context).to_big_uint();

        DLogProof::prove(&ec_context, &pk, &sk)
    }
}