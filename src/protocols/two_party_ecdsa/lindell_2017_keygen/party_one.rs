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

// TODO: remove the next line when unit test will be done
#[allow(dead_code)]
pub struct FirstMsgCommitments {
    pub pk_commitment: BigInt,
    pk_commitment_blind_factor: BigInt,

    pub zk_pok_commitment: BigInt,
    zk_pok_blind_factor: BigInt,

    pk: PK,
    pk_t_rand_commitment : PK,
    challenge_response : BigInt,
}

impl FirstMsgCommitments {
    pub fn create(ec_context: &EC) -> FirstMsgCommitments {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context).to_big_uint();

        let pk_commitment_blind_factor = BigInt::sample(R_BYTES_SIZE);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.to_point().x, &pk_commitment_blind_factor);

        // Implementation of Schnorr protocol
        let mut pk_t_rand_commitment = PK::to_key(&ec_context, &EC::get_base_point());
        let sk_t_rand_commitment = pk_t_rand_commitment.randomize(&ec_context).to_big_uint();

        let challenge = HSha256::create_hash(
            vec![&pk_t_rand_commitment.to_point().x, &EC::get_base_point().x, &pk.to_point().x]);

        let challenge_response = BigInt::mod_sub(
            &sk_t_rand_commitment, &BigInt::mod_mul(
                &challenge, &sk, &EC::get_q()),
            &EC::get_q());

        let zk_pok_blind_factor = BigInt::sample(R_BYTES_SIZE);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk_t_rand_commitment.to_point().x, &zk_pok_blind_factor);

        FirstMsgCommitments {
            pk_commitment,
            pk_commitment_blind_factor,

            zk_pok_commitment,
            zk_pok_blind_factor,

            pk,
            pk_t_rand_commitment,
            challenge_response
        }
    }
}