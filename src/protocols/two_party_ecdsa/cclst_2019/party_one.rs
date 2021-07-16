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
use std::cmp;

use class_group::primitives::cl_dl_public_setup::{
    decrypt, verifiably_encrypt, CLDLProof, CLGroup, Ciphertext as CLCiphertext, PK, SK,
};

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMessage;
use super::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMessage;
use super::SECURITY_BITS;
use crate::Error::{self, InvalidSig};

//****************** Begin: Party One structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof<GE>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {
    pub comm_witness: CommWitness,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HSMCL {
    pub public: PK,
    pub secret: SK,
    pub encrypted_share: CLCiphertext,
    pub cl_group: CLGroup,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HSMCLPublic {
    pub cl_pub_key: PK,
    pub proof: CLDLProof,
    pub encrypted_share: CLCiphertext,
    pub cl_group: CLGroup,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub s: BigInt,
    pub r: BigInt,
    pub recid: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: BigInt,
    pub r: BigInt,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Party1Private {
    x1: FE,
    hsmcl_pub: PK,
    hsmcl_priv: SK,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLFirstMessage {
    pub c_hat: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLdecommit {
    pub q_hat: GE,
    pub blindness: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLSecondMessage {
    pub decommit: PDLdecommit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphEcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenFirstMsg {
    pub d_log_proof: ECDDHProof<GE>,
    pub public_share: GE,
    pub c: GE, //c = secret_share * base_point2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenSecondMsg {}

//****************** End: Party One structs ******************//

impl KeyGenFirstMsg {
    pub fn create_commitments() -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base: GE = ECPoint::generator();

        let secret_share: FE = ECScalar::new_random();
        //in Lindell's protocol range proof works only for x1<q/3
        let secret_share: FE =
            ECScalar::from(&secret_share.to_big_int().div_floor(&BigInt::from(3)));

        let public_share = base.scalar_mul(&secret_share.get_element());

        let d_log_proof = DLogProof::prove(&secret_share);
        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &zk_pok_blind_factor,
        );
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share.clone(),
                d_log_proof,
            },
            ec_key_pair,
        )
    }

    pub fn create_commitments_with_fixed_secret_share(
        secret_share: FE,
    ) -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base.scalar_mul(&secret_share.get_element());

        let d_log_proof = DLogProof::prove(&secret_share);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &zk_pok_blind_factor,
        );

        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share.clone(),
                d_log_proof,
            },
            ec_key_pair,
        )
    }
}

impl KeyGenSecondMsg {
    pub fn verify_and_decommit(
        comm_witness: CommWitness,
        proof: &DLogProof<GE>,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(proof)?;
        Ok(KeyGenSecondMsg { comm_witness })
    }
}

pub fn compute_pubkey(party_one_private: &Party1Private, other_share_public_share: &GE) -> GE {
    other_share_public_share * &party_one_private.x1
}

impl Party1Private {
    pub fn set_private_key(ec_key: &EcKeyPair, hsmcl: &HSMCL) -> Party1Private {
        Party1Private {
            x1: ec_key.secret_share.clone(),
            hsmcl_pub: hsmcl.public.clone(),
            hsmcl_priv: hsmcl.secret.clone(),
        }
    }
}

impl HSMCL {
    pub fn generate_keypair_and_encrypted_share_and_proof(
        keygen: &EcKeyPair,
        seed: &BigInt,
    ) -> (HSMCL, HSMCLPublic) {
        let cl_group = CLGroup::new_from_setup(&1348, &seed);
        let (secret_key, public_key) = cl_group.keygen();
        let (ciphertext, proof) = verifiably_encrypt(
            &cl_group,
            &public_key,
            (&keygen.secret_share, &keygen.public_share),
        );

        (
            HSMCL {
                cl_group: cl_group.clone(),
                public: public_key.clone(),
                secret: secret_key.clone(),
                encrypted_share: ciphertext.clone(),
            },
            HSMCLPublic {
                cl_pub_key: public_key.clone(),
                proof,
                encrypted_share: ciphertext.clone(),
                cl_group,
            },
        )
    }
}

impl EphKeyGenFirstMsg {
    pub fn create() -> (EphKeyGenFirstMsg, EphEcKeyPair) {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = &base * &secret_share;
        let h: GE = GE::base_point2();
        let w = ECDDHWitness {
            x: secret_share.clone(),
        };
        let c = &h * &secret_share;
        let delta = ECDDHStatement {
            g1: base.clone(),
            h1: public_share.clone(),
            g2: h.clone(),
            h2: c.clone(),
        };
        let d_log_proof = ECDDHProof::prove(&w, &delta);
        let ec_key_pair = EphEcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (
            EphKeyGenFirstMsg {
                d_log_proof,
                public_share,
                c,
            },
            ec_key_pair,
        )
    }
}

impl EphKeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        party_two_first_message: &Party2EphKeyGenFirstMessage,
        party_two_second_message: &Party2EphKeyGenSecondMessage,
    ) -> Result<EphKeyGenSecondMsg, ProofError> {
        let party_two_pk_commitment = &party_two_first_message.pk_commitment;
        let party_two_zk_pok_commitment = &party_two_first_message.zk_pok_commitment;
        let party_two_zk_pok_blind_factor =
            &party_two_second_message.comm_witness.zk_pok_blind_factor;
        let party_two_public_share = &party_two_second_message.comm_witness.public_share;
        let party_two_pk_commitment_blind_factor = &party_two_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_two_d_log_proof = &party_two_second_message.comm_witness.d_log_proof;
        let mut flag = true;
        match party_two_pk_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_two_public_share.bytes_compressed_to_big_int(),
                &party_two_pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_two_zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &HSha256::create_hash_from_ge(&[
                    &party_two_d_log_proof.a1,
                    &party_two_d_log_proof.a2,
                ])
                .to_big_int(),
                &party_two_zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        let delta = ECDDHStatement {
            g1: GE::generator(),
            h1: party_two_public_share.clone(),
            g2: GE::base_point2(),
            h2: party_two_second_message.comm_witness.c.clone(),
        };
        party_two_d_log_proof.verify(&delta)?;
        Ok(EphKeyGenSecondMsg {})
    }
}

impl Signature {
    pub fn compute(
        hsmcl: &HSMCL,
        party_one_private: &Party1Private,
        partial_sig_c3: CLCiphertext,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &GE,
    ) -> Signature {
        //compute r = k2* R1
        let mut r = ephemeral_other_public_share.clone();
        r = r.scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().unwrap().mod_floor(&FE::q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&FE::q())
            .unwrap();
        let s_tag = decrypt(
            &hsmcl.cl_group,
            &party_one_private.hsmcl_priv,
            &partial_sig_c3,
        );
        let s_tag_tag = BigInt::mod_mul(&k1_inv, &s_tag.to_big_int(), &FE::q());
        let s = cmp::min(s_tag_tag.clone(), FE::q().clone() - s_tag_tag.clone());
        Signature { s, r: rx }
    }
}

pub fn verify(signature: &Signature, pubkey: &GE, message: &BigInt) -> Result<(), Error> {
    let s_fe: FE = ECScalar::from(&signature.s);
    let rx_fe: FE = ECScalar::from(&signature.r);

    let s_inv_fe = s_fe.invert();
    let e_fe: FE = ECScalar::from(&message.mod_floor(&FE::q()));
    let u1 = GE::generator() * e_fe * s_inv_fe;
    let u2 = *pubkey * rx_fe * s_inv_fe;

    // second condition is against malleability
    let rx_bytes = &BigInt::to_bytes(&signature.r)[..];
    let u1_plus_u2_bytes = &BigInt::to_bytes(&(u1 + u2).x_coor().unwrap())[..];

    if rx_bytes.ct_eq(&u1_plus_u2_bytes).unwrap_u8() == 1
        && signature.s < FE::q() - signature.s.clone()
    {
        Ok(())
    } else {
        Err(InvalidSig)
    }
}
