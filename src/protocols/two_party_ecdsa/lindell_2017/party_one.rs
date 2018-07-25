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

use cryptography_utils::BigInt;

use cryptography_utils::EC;
use cryptography_utils::PK;
use cryptography_utils::SK;

const SECURITY_BITS: usize = 256;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use super::party_two;
use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use paillier::*;
use std::cmp;

// TODO: remove the next line when unit test will be done
#[allow(dead_code)]
#[derive(Debug)]
pub struct KeyGenFirstMsg {
    pub public_share: PK,
    secret_share: SK,
    pub pk_commitment: BigInt,
    pk_commitment_blind_factor: BigInt,

    pub zk_pok_commitment: BigInt,
    zk_pok_blind_factor: BigInt,

    d_log_proof: DLogProof,
}

impl KeyGenFirstMsg {
    pub fn create_commitments(ec_context: &EC) -> KeyGenFirstMsg {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());

        //in Lindell's protocol range proof works only for x1<q/3
        let sk = SK::from_big_int(
            ec_context,
            &BigInt::sample_below(&EC::get_q().div_floor(&BigInt::from(3))),
        );
        assert!(pk.mul_assign(ec_context, &sk).is_ok());

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

#[derive(Debug)]
pub struct KeyGenSecondMsg {
    pub d_log_proof_result: Result<(), ProofError>,
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: PK,
    pub d_log_proof: DLogProof,
}

impl KeyGenSecondMsg {
    pub fn verify_and_decommit(
        ec_context: &EC,
        first_message: &KeyGenFirstMsg,
        proof: &DLogProof,
    ) -> KeyGenSecondMsg {
        KeyGenSecondMsg {
            d_log_proof_result: DLogProof::verify(ec_context, proof),
            pk_commitment_blind_factor: first_message.pk_commitment_blind_factor.clone(),
            zk_pok_blind_factor: first_message.zk_pok_blind_factor.clone(),
            public_share: first_message.public_share.clone(),
            d_log_proof: first_message.d_log_proof.clone(),
        }
    }
}

pub fn compute_pubkey(
    ec_context: &EC,
    local_share: &KeyGenFirstMsg,
    other_share: &party_two::KeyGenFirstMsg,
) -> PK {
    let mut pubkey = other_share.public_share.clone();
    assert!(
        pubkey
            .mul_assign(ec_context, &local_share.secret_share)
            .is_ok()
    );
    return pubkey;
}

#[derive(Debug)]
pub struct PaillierKeyPair {
    pub ek: EncryptionKey,
    dk: DecryptionKey,
    pub encrypted_share: BigInt,
    randomness: BigInt,
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
            &EC::get_q(),
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

#[derive(Debug)]
pub struct Signature {
    pub s: BigInt,
    pub r: BigInt,
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
        assert!(
            r.mul_assign(ec_context, &ephemeral_local_share.secret_share)
                .is_ok()
        );

        let rx = r.to_point().x.mod_floor(&EC::get_q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&EC::get_q())
            .unwrap();
        let s_tag = Paillier::decrypt(&keypair.dk, &RawCiphertext::from(&partial_sig.c3));
        let s_tag_tag = BigInt::mod_mul(&k1_inv, &s_tag.0, &EC::get_q());
        let s = cmp::min(s_tag_tag.clone(), &EC::get_q().clone() - s_tag_tag.clone());

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
        .invert(&EC::get_q())
        .unwrap()
        .mod_floor(&EC::get_q());
    let a = message.mod_floor(&EC::get_q());
    let u1 = BigInt::mod_mul(&a, &b, &EC::get_q());
    let u2 = BigInt::mod_mul(&signature.r, &b, &EC::get_q());
    // can be faster using shamir trick
    let mut point1 = PK::to_key(ec_context, &EC::get_base_point());
    assert!(
        point1
            .mul_assign(ec_context, &SK::from_big_int(ec_context, &u1))
            .is_ok()
    );

    let mut point2 = *pubkey;
    assert!(
        point2
            .mul_assign(ec_context, &SK::from_big_int(ec_context, &u2))
            .is_ok()
    );

    if signature.r == point1.combine(ec_context, &point2).unwrap().to_point().x {
        Ok(())
    } else {
        Err(ProofError)
    }
}
