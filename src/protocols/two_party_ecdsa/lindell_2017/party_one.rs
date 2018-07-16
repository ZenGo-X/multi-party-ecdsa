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

const SECURITY_BITS : usize = 256;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use super::party_two;
use paillier::*;
use std::cmp;

// TODO: remove the next line when unit test will be done
#[allow(dead_code)]
#[derive(Debug)]
pub struct KeyGenFirstMsg{
    pub public_share: PK,
    secret_share : SK,
    pub pk_commitment : BigInt,
     pk_commitment_blind_factor : BigInt,

    pub zk_pok_commitment : BigInt,
    zk_pok_blind_factor : BigInt,

    d_log_proof : DLogProof
}

impl KeyGenFirstMsg {
    pub fn create_commitments(ec_context: &EC) -> KeyGenFirstMsg {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context);

        let d_log_proof = DLogProof::prove(&ec_context, &pk, &sk);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.to_point().x, &pk_commitment_blind_factor);

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.to_point().x, &zk_pok_blind_factor);

        KeyGenFirstMsg{
            public_share: pk,
            secret_share: sk,
            pk_commitment,
            pk_commitment_blind_factor,

            zk_pok_commitment,
            zk_pok_blind_factor,

            d_log_proof
        }
    }
}

#[derive(Debug)]
pub struct KeyGenSecondMsg {
    pub d_log_proof_result : Result<(), ProofError>,
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: PK,
    pub d_log_proof: DLogProof
}

impl KeyGenSecondMsg {
    pub fn verify_and_decommit(ec_context: &EC, first_message: &KeyGenFirstMsg , proof: &DLogProof) -> KeyGenSecondMsg {
        KeyGenSecondMsg {
            d_log_proof_result: DLogProof::verify(ec_context, proof),
            pk_commitment_blind_factor: first_message.pk_commitment_blind_factor.clone(),
            zk_pok_blind_factor: first_message.zk_pok_blind_factor.clone(),
            public_share: first_message.public_share.clone(),
            d_log_proof : first_message.d_log_proof.clone()
        }
    }
}


#[derive(Debug)]
pub struct PaillierKeyPair {
    pub ek : EncryptionKey,
    dk: DecryptionKey
}

impl PaillierKeyPair {
    pub fn generate() -> PaillierKeyPair {
        let (ek, dk) = Paillier::keypair().keys();
        PaillierKeyPair {ek,dk}
    }
}

pub fn compute_pubkey(ec_context: &EC, local_share: &KeyGenFirstMsg, other_share : &party_two::KeyGenFirstMsg) -> PK{
    let mut pubkey = other_share.public_share.clone();
    pubkey.mul_assign(ec_context, &local_share.secret_share);
    return pubkey;
}


pub fn paillier_encrypted_share(ek: &EncryptionKey, keygen: &KeyGenFirstMsg) -> RawCiphertext{
    Paillier::encrypt(ek, &RawPlaintext(keygen.secret_share.to_big_int()))
}


#[derive(Debug)]
pub struct Signature{
    pub s : BigInt,
    pub r : BigInt
}

impl Signature {
    pub fn compute(ec_context: &EC, keypair: &PaillierKeyPair, partial_sig: &party_two::PartialSig, ephemeral_local_share: &KeyGenFirstMsg, ephemeral_other_share: &party_two::KeyGenFirstMsg) -> Signature {
        //compute R = k2* R1
        let mut R = ephemeral_other_share.public_share.clone();
        R.mul_assign(ec_context, &ephemeral_local_share.secret_share);
        let rx = R.to_point().x.mod_floor(&EC::get_q());

        let k1_inv = &ephemeral_local_share.secret_share.to_big_int().invert(&EC::get_q()).unwrap();
        let s_tag = Paillier::decrypt(&keypair.dk, &partial_sig.c3);
        let s_tag_tag = BigInt::mod_mul(&k1_inv, &s_tag.0, &EC::get_q()) ;
        let s = cmp::min(s_tag_tag.clone(), &EC::get_q().clone()-s_tag_tag.clone());

        Signature {
            s,
            r: rx
        }
    }
}

pub fn verify(ec_context: &EC, signature: &Signature, pubkey: &PK, message: &BigInt) -> Result<(), ProofError>{

    let B = signature.s.invert(&EC::get_q()).unwrap().mod_floor(&EC::get_q());
    let A = message.mod_floor(&EC::get_q());
    let u1 = BigInt::mod_mul(&A, &B, &EC::get_q());
    let u2 = BigInt::mod_mul(&signature.r, &B, &EC::get_q());
    // can be faster using shamir trick
    let mut point1 = PK::to_key(ec_context, &EC::get_base_point());
    point1.mul_assign(ec_context, &SK::from_big_int(ec_context, &u1));
    let mut point2 = *pubkey;
    point2.mul_assign(ec_context, &SK::from_big_int(ec_context, &u2));
    if signature.r == point1.combine(ec_context, &point2).unwrap().to_point().x{
        Ok(())
    } else {
        Err(ProofError)
    }
}
