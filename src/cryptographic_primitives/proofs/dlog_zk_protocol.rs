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

//! This is implementation of Schnorr's identification protocol for elliptic curve groups or a
//! sigma protocol for Proof of knowledge of the discrete log of an Elliptic-curve point:
//! C.P. Schnorr. Efficient Identification and Signatures for Smart Cards. In
//! CRYPTO 1989, Springer (LNCS 435), pages 239–252, 1990.
//! https://pdfs.semanticscholar.org/8d69/c06d48b618a090dd19185aea7a13def894a5.pdf.
//!
//! The protocol is using Fiat-Shamir Transform: Amos Fiat and Adi Shamir.
//! How to prove yourself: Practical solutions to identification and signature problems.
//! In Advances in Cryptology - CRYPTO ’86, Santa Barbara, California, USA, 1986, Proceedings,
//! pages 186–194, 1986.

use ::BigInt;

use ::EC;
use ::PK;
use ::SK;

use super::ProofError;

use arithmetic::traits::Modulo;

use elliptic::curves::traits::*;

use cryptographic_primitives::hashing::hash_sha256::HSha256;
use cryptographic_primitives::hashing::traits::Hash;

#[derive(Debug)]
pub struct DLogProof {
    pub pk : PK,
    pub pk_t_rand_commitment : PK,
    pub challenge_response : BigInt
}

pub trait ProveDLog {
    fn prove(ec_context: &EC, pk: &PK, sk: &SK) -> DLogProof;

    fn verify(ec_context: &EC, proof: &DLogProof) -> Result<(), ProofError>;
}

impl ProveDLog for DLogProof {
    fn prove(ec_context: &EC, pk: &PK, sk: &SK) -> DLogProof {
        let mut pk_t_rand_commitment = PK::to_key(&ec_context, &EC::get_base_point());
        let sk_t_rand_commitment = pk_t_rand_commitment.randomize(&ec_context).to_big_int();

        let challenge = HSha256::create_hash(
            vec![&pk_t_rand_commitment.to_point().x, &EC::get_base_point().x, &pk.to_point().x]);

        let challenge_response = BigInt::mod_sub(
            &sk_t_rand_commitment, &BigInt::mod_mul(
                &challenge, &sk.to_big_int(), &EC::get_q()),
            &EC::get_q());

        DLogProof {
            pk : *pk,
            pk_t_rand_commitment,
            challenge_response
        }
    }

    fn verify(ec_context: &EC, proof: &DLogProof) -> Result<(), ProofError> {
        let challenge = HSha256::create_hash(
            vec![
                &proof.pk_t_rand_commitment.to_point().x,
                &EC::get_base_point().x,
                &proof.pk.to_point().x]);

        let mut pk_challenge = proof.pk.clone();
        assert!(pk_challenge.mul_assign(
            ec_context, &SK::from_big_int(ec_context, &challenge)).is_ok());


        let mut pk_verifier = PK::to_key(ec_context, &EC::get_base_point());
        assert!(pk_verifier.mul_assign(
            ec_context, &SK::from_big_int(ec_context, &proof.challenge_response)).is_ok());

        let pk_verifier = match pk_verifier.combine(ec_context, &pk_challenge) {
            Ok(pk_verifier) => pk_verifier,
            _error => return Err(ProofError),
        };

        if pk_verifier == proof.pk_t_rand_commitment {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}