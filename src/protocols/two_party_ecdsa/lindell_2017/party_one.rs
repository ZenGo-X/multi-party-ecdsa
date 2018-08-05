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

use paillier::*;
use std::cmp;

const SECURITY_BITS: usize = 256;

use cryptography_utils::arithmetic::serde::serde_bigint;
use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::elliptic::curves::serde::{serde_public_key, serde_secret_key};
use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use cryptography_utils::BigInt;
use cryptography_utils::EC;
use cryptography_utils::PK;
use cryptography_utils::SK;

use super::party_two;

//****************** Begin: Party One structs ******************//
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    #[serde(with = "serde_public_key")]
    public_share: PK,

    #[serde(with = "serde_secret_key")]
    secret_share: SK,

    #[serde(with = "serde_bigint")]
    pub pk_commitment: BigInt,

    #[serde(with = "serde_bigint")]
    pk_commitment_blind_factor: BigInt,

    #[serde(with = "serde_bigint")]
    pub zk_pok_commitment: BigInt,

    #[serde(with = "serde_bigint")]
    zk_pok_blind_factor: BigInt,

    d_log_proof: DLogProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {
    #[serde(with = "serde_bigint")]
    pub pk_commitment_blind_factor: BigInt,

    #[serde(with = "serde_bigint")]
    pub zk_pok_blind_factor: BigInt,

    #[serde(with = "serde_public_key")]
    pub public_share: PK,

    pub d_log_proof: DLogProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaillierKeyPair {

    pub ek: EncryptionKey,
    dk: DecryptionKey,

    #[serde(with = "serde_bigint")]
    pub encrypted_share: BigInt,

    #[serde(with = "serde_bigint")]
    randomness: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    #[serde(with = "serde_bigint")]
    pub s: BigInt,

    #[serde(with = "serde_bigint")]
    pub r: BigInt,
}

//****************** End: Party One structs ******************//

impl KeyGenFirstMsg {
    pub fn create_commitments(ec_context: &EC) -> KeyGenFirstMsg {
        let mut pk = PK::to_key(&PK::get_base_point());

        //in Lindell's protocol range proof works only for x1<q/3
        let sk = SK::from_big_int(&BigInt::sample_below(
            &SK::get_q().div_floor(&BigInt::from(3)),
        ));
        pk.mul_assign(ec_context, &sk).expect("Assignment expected");

        let d_log_proof = DLogProof::prove(&ec_context, &pk, &sk);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.to_point().x,
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.to_point().x,
            &zk_pok_blind_factor,
        );

        KeyGenFirstMsg {
            public_share: pk,
            secret_share: sk,
            pk_commitment,
            pk_commitment_blind_factor,

            zk_pok_commitment,
            zk_pok_blind_factor,

            d_log_proof,
        }
    }
}

impl KeyGenSecondMsg {
    pub fn verify_and_decommit(
        ec_context: &EC,
        first_message: &KeyGenFirstMsg,
        proof: &DLogProof,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(ec_context, proof)?;
        Ok(KeyGenSecondMsg {
            pk_commitment_blind_factor: first_message.pk_commitment_blind_factor.clone(),
            zk_pok_blind_factor: first_message.zk_pok_blind_factor.clone(),
            public_share: first_message.public_share.clone(),
            d_log_proof: first_message.d_log_proof.clone(),
        })
    }
}

pub fn compute_pubkey(
    ec_context: &EC,
    local_share: &KeyGenFirstMsg,
    other_share: &party_two::KeyGenFirstMsg,
) -> PK {
    let mut pubkey = other_share.public_share.clone();
    pubkey
        .mul_assign(ec_context, &local_share.secret_share)
        .expect("Failed to multiply and assign");

    return pubkey;
}

impl PaillierKeyPair {
    pub fn generate_keypair_and_encrypted_share(keygen: &KeyGenFirstMsg) -> PaillierKeyPair {
        let (ek, dk) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek);

        let encrypted_share = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(keygen.secret_share.to_big_int()),
            &randomness,
        ).0
        .into_owned();

        PaillierKeyPair {
            ek,
            dk,
            encrypted_share,
            randomness: randomness.0,
        }
    }

    pub fn generate_range_proof(
        paillier_context: &PaillierKeyPair,
        keygen: &KeyGenFirstMsg,
    ) -> (EncryptedPairs, ChallengeBits, Proof) {
        let (encrypted_pairs, challenge, proof) = Paillier::prover(
            &paillier_context.ek,
            &SK::get_q(),
            &keygen.secret_share.to_big_int(),
            &paillier_context.randomness,
        );

        (encrypted_pairs, challenge, proof)
    }

    pub fn generate_proof_correct_key(
        paillier_context: &PaillierKeyPair,
        challenge: &Challenge,
    ) -> Result<CorrectKeyProof, CorrectKeyProofError> {
        Paillier::prove(&paillier_context.dk, challenge)
    }
}

impl Signature {
    pub fn compute(
        ec_context: &EC,
        keypair: &PaillierKeyPair,
        partial_sig: &party_two::PartialSig,
        ephemeral_local_share: &KeyGenFirstMsg,
        ephemeral_other_share: &party_two::KeyGenFirstMsg,
    ) -> Signature {
        //compute r = k2* R1
        let mut r = ephemeral_other_share.public_share.clone();
        r.mul_assign(ec_context, &ephemeral_local_share.secret_share)
            .expect("Failed to multiply and assign");

        let rx = r.to_point().x.mod_floor(&SK::get_q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&SK::get_q())
            .unwrap();
        let s_tag = Paillier::decrypt(&keypair.dk, &RawCiphertext::from(&partial_sig.c3));
        let s_tag_tag = BigInt::mod_mul(&k1_inv, &s_tag.0, &SK::get_q());
        let s = cmp::min(s_tag_tag.clone(), &SK::get_q().clone() - s_tag_tag.clone());

        Signature { s, r: rx }
    }
}

pub fn verify(
    ec_context: &EC,
    signature: &Signature,
    pubkey: &PK,
    message: &BigInt,
) -> Result<(), ProofError> {
    let b = signature
        .s
        .invert(&SK::get_q())
        .unwrap()
        .mod_floor(&SK::get_q());
    let a = message.mod_floor(&SK::get_q());
    let u1 = BigInt::mod_mul(&a, &b, &SK::get_q());
    let u2 = BigInt::mod_mul(&signature.r, &b, &SK::get_q());
    // can be faster using shamir trick
    let mut point1 = PK::to_key(&PK::get_base_point());

    point1
        .mul_assign(ec_context, &SK::from_big_int(&u1))
        .expect("Failed to multiply and assign");

    let mut point2 = *pubkey;
    point2
        .mul_assign(ec_context, &SK::from_big_int(&u2))
        .expect("Failed to multiply and assign");

    if signature.r == point1.combine(ec_context, &point2).unwrap().to_point().x {
        Ok(())
    } else {
        Err(ProofError)
    }
}
