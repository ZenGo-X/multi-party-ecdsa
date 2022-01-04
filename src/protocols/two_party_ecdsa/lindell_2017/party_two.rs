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

use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use paillier::Paillier;
use paillier::{Add, Encrypt, Mul};
use paillier::{EncryptionKey, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zk_paillier::zkproofs::{IncorrectProof, NiCorrectKeyProof};

use super::party_one::EphKeyGenFirstMsg as Party1EphKeyGenFirstMsg;
use super::party_one::KeyGenFirstMsg as Party1KeyGenFirstMessage;
use super::party_one::KeyGenSecondMsg as Party1KeyGenSecondMessage;
use super::SECURITY_BITS;
use crate::utilities::mta::{MessageA, MessageB};

use crate::utilities::zk_pdl_with_slack::PDLwSlackProof;
use crate::utilities::zk_pdl_with_slack::PDLwSlackStatement;
use thiserror::Error;
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

#[derive(Error, Debug)]
pub enum PartyTwoError {
    #[error("party two pdl verify failed (lindell 2017)")]
    PdlVerify,
}

const PAILLIER_KEY_SIZE: usize = 2048;
//****************** Begin: Party Two structs ******************//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: Point<Secp256k1>,
    secret_share: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub d_log_proof: DLogProof<Secp256k1, Sha256>,
    pub public_share: Point<Secp256k1>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaillierPublic {
    pub ek: EncryptionKey,
    pub encrypted_secret_share: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialSig {
    pub c3: BigInt,
}

#[derive(Serialize, Deserialize)]
pub struct Party2Private {
    x2: Scalar<Secp256k1>,
}
#[derive(Debug)]
pub struct PDLchallenge {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
    a: BigInt,
    b: BigInt,
    blindness: BigInt,
    q_tag: Point<Secp256k1>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLFirstMessage {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLdecommit {
    pub a: BigInt,
    pub b: BigInt,
    pub blindness: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLSecondMessage {
    pub decommit: PDLdecommit,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphEcKeyPair {
    pub public_share: Point<Secp256k1>,
    secret_share: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphCommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: Point<Secp256k1>,
    pub d_log_proof: ECDDHProof<Secp256k1, Sha256>,
    pub c: Point<Secp256k1>, //c = secret_share * base_point2
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphKeyGenFirstMsg {
    pub pk_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenSecondMsg {
    pub comm_witness: EphCommWitness,
}

//****************** End: Party Two structs ******************//

impl KeyGenFirstMsg {
    pub fn create() -> (KeyGenFirstMsg, EcKeyPair) {
        let base = Point::generator();
        let secret_share = Scalar::<Secp256k1>::random();
        let public_share = base * &secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (
            KeyGenFirstMsg {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }

    pub fn create_with_fixed_secret_share(
        secret_share: Scalar<Secp256k1>,
    ) -> (KeyGenFirstMsg, EcKeyPair) {
        let base = Point::generator();
        let public_share = base * &secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (
            KeyGenFirstMsg {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }
}

impl KeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        party_one_first_message: &Party1KeyGenFirstMessage,
        party_one_second_message: &Party1KeyGenSecondMessage,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        let party_one_pk_commitment = &party_one_first_message.pk_commitment;
        let party_one_zk_pok_commitment = &party_one_first_message.zk_pok_commitment;
        let party_one_zk_pok_blind_factor =
            &party_one_second_message.comm_witness.zk_pok_blind_factor;
        let party_one_public_share = &party_one_second_message.comm_witness.public_share;
        let party_one_pk_commitment_blind_factor = &party_one_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_one_d_log_proof = &party_one_second_message.comm_witness.d_log_proof;

        let mut flag = true;
        if party_one_pk_commitment
            != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(party_one_public_share.to_bytes(true).as_ref()),
                party_one_pk_commitment_blind_factor,
            )
        {
            flag = false
        }
        if party_one_zk_pok_commitment
            != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(
                    party_one_d_log_proof
                        .pk_t_rand_commitment
                        .to_bytes(true)
                        .as_ref(),
                ),
                party_one_zk_pok_blind_factor,
            )
        {
            flag = false
        }

        if !flag {
            return Err(ProofError);
        }

        DLogProof::verify(party_one_d_log_proof)?;
        Ok(KeyGenSecondMsg {})
    }
}

pub fn compute_pubkey(
    local_share: &EcKeyPair,
    other_share_public_share: &Point<Secp256k1>,
) -> Point<Secp256k1> {
    let pubkey = other_share_public_share;
    pubkey * &local_share.secret_share
}

impl Party2Private {
    pub fn set_private_key(ec_key: &EcKeyPair) -> Party2Private {
        Party2Private {
            x2: ec_key.secret_share.clone(),
        }
    }

    pub fn update_private_key(party_two_private: &Party2Private, factor: &BigInt) -> Party2Private {
        let factor_fe = Scalar::<Secp256k1>::from(factor);
        Party2Private {
            x2: &party_two_private.x2 * &factor_fe,
        }
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: usize,
        num_of_segments: usize,
        pub_ke_y: &Point<Secp256k1>,
        g: &Point<Secp256k1>,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.x2, &segment_size, num_of_segments, pub_ke_y, g)
    }

    // used to transform lindell master key to gg18 master key
    pub fn to_mta_message_b(
        &self,
        ek: &EncryptionKey,
        ciphertext: &BigInt,
    ) -> (MessageB, Scalar<Secp256k1>) {
        let message_a = MessageA {
            c: ciphertext.clone(),
            range_proofs: vec![],
        };
        let (a, b, _, _) = MessageB::b(&self.x2, ek, message_a, &[]).unwrap();
        (a, b)
    }
}

impl PaillierPublic {
    pub fn pdl_verify(
        composite_dlog_proof: &CompositeDLogProof,
        pdl_w_slack_statement: &PDLwSlackStatement,
        pdl_w_slack_proof: &PDLwSlackProof,
        paillier_public: &PaillierPublic,
        q1: &Point<Secp256k1>,
    ) -> Result<(), PartyTwoError> {
        if pdl_w_slack_statement.ek != paillier_public.ek
            || pdl_w_slack_statement.ciphertext != paillier_public.encrypted_secret_share
            || &pdl_w_slack_statement.Q != q1
        {
            return Err(PartyTwoError::PdlVerify);
        }
        let dlog_statement = DLogStatement {
            N: pdl_w_slack_statement.N_tilde.clone(),
            g: pdl_w_slack_statement.h1.clone(),
            ni: pdl_w_slack_statement.h2.clone(),
        };
        if composite_dlog_proof.verify(&dlog_statement).is_ok()
            && pdl_w_slack_proof.verify(pdl_w_slack_statement).is_ok()
        {
            Ok(())
        } else {
            Err(PartyTwoError::PdlVerify)
        }
    }

    pub fn verify_ni_proof_correct_key(
        proof: NiCorrectKeyProof,
        ek: &EncryptionKey,
    ) -> Result<(), IncorrectProof> {
        //
        if ek.n.bit_length() < PAILLIER_KEY_SIZE - 1 {
            return Err(IncorrectProof);
        };
        proof.verify(ek, zk_paillier::zkproofs::SALT_STRING)
    }
}

impl EphKeyGenFirstMsg {
    pub fn create_commitments() -> (EphKeyGenFirstMsg, EphCommWitness, EphEcKeyPair) {
        let base = Point::generator();

        let secret_share = Scalar::<Secp256k1>::random();

        let public_share = base * &secret_share;

        let h = Point::<Secp256k1>::base_point2();

        let c = h * &secret_share;
        let w = ECDDHWitness {
            x: secret_share.clone(),
        };
        let delta = ECDDHStatement {
            g1: base.to_point(),
            h1: public_share.clone(),
            g2: h.clone(),
            h2: c.clone(),
        };
        let d_log_proof = ECDDHProof::prove(&w, &delta);

        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(public_share.to_bytes(true).as_ref()),
                &pk_commitment_blind_factor,
            );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &Sha256::new()
                    .chain_points([&d_log_proof.a1, &d_log_proof.a2])
                    .result_bigint(),
                &zk_pok_blind_factor,
            );

        let ec_key_pair = EphEcKeyPair {
            public_share,
            secret_share,
        };
        (
            EphKeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            EphCommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share.clone(),
                d_log_proof,
                c,
            },
            ec_key_pair,
        )
    }
}

impl EphKeyGenSecondMsg {
    pub fn verify_and_decommit(
        comm_witness: EphCommWitness,
        party_one_first_message: &Party1EphKeyGenFirstMsg,
    ) -> Result<EphKeyGenSecondMsg, ProofError> {
        let delta = ECDDHStatement {
            g1: Point::generator().to_point(),
            h1: party_one_first_message.public_share.clone(),
            g2: Point::<Secp256k1>::base_point2().clone(),
            h2: party_one_first_message.c.clone(),
        };
        party_one_first_message.d_log_proof.verify(&delta)?;
        Ok(EphKeyGenSecondMsg { comm_witness })
    }
}

impl PartialSig {
    pub fn compute(
        ek: &EncryptionKey,
        encrypted_secret_share: &BigInt,
        local_share: &Party2Private,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &Point<Secp256k1>,
        message: &BigInt,
    ) -> PartialSig {
        let q = Scalar::<Secp256k1>::group_order();
        //compute r = k2* R1
        let r = ephemeral_other_public_share * &ephemeral_local_share.secret_share;

        let rx = r.x_coord().unwrap().mod_floor(q);
        let rho = BigInt::sample_below(&q.pow(2));
        let k2_inv = BigInt::mod_inv(&ephemeral_local_share.secret_share.to_bigint(), q).unwrap();
        let partial_sig = rho * q + BigInt::mod_mul(&k2_inv, message, q);

        let c1 = Paillier::encrypt(ek, RawPlaintext::from(partial_sig));
        let v = BigInt::mod_mul(
            &k2_inv,
            &BigInt::mod_mul(&rx, &local_share.x2.to_bigint(), q),
            q,
        );
        let c2 = Paillier::mul(
            ek,
            RawCiphertext::from(encrypted_secret_share.clone()),
            RawPlaintext::from(v),
        );
        //c3:
        PartialSig {
            c3: Paillier::add(ek, c2, c1).0.into_owned(),
        }
    }
}
