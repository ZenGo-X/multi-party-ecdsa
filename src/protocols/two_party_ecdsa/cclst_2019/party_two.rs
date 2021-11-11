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
use super::party_one::HSMCLPublic;
use class_group::primitives::cl_dl_public_setup::PK as HSMCLPK;
use class_group::primitives::cl_dl_public_setup::{
    encrypt, eval_scal, eval_sum, CLGroup, Ciphertext as CLCiphertext,
};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::party_one::EphKeyGenFirstMsg as Party1EphKeyGenFirstMsg;
use super::party_one::KeyGenFirstMsg as Party1KeyGenFirstMessage;
use super::party_one::KeyGenSecondMsg as Party1KeyGenSecondMessage;
use super::SECURITY_BITS;

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
pub struct Party2Public {
    pub group: CLGroup,
    pub ek: HSMCLPK,
    pub encrypted_secret_share: CLCiphertext,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialSig {
    pub c3: CLCiphertext,
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
    other_share_public_share * &local_share.secret_share
}

impl Party2Private {
    pub fn set_private_key(ec_key: &EcKeyPair) -> Party2Private {
        Party2Private {
            x2: ec_key.secret_share.clone(),
        }
    }
}

impl Party2Public {
    pub fn verify_setup_and_zkcldl_proof(
        hsmcl_public: &HSMCLPublic,
        seed: &BigInt,
        party1_ec_pubkey: &Point<Secp256k1>,
    ) -> Result<Self, ProofError> {
        let setup_verify = hsmcl_public.cl_group.setup_verify(seed);

        let proof_verify = hsmcl_public.proof.verify(
            &hsmcl_public.cl_group,
            &hsmcl_public.cl_pub_key,
            &hsmcl_public.encrypted_share,
            party1_ec_pubkey,
        );
        if proof_verify.is_ok() && setup_verify.is_ok() {
            Ok(Party2Public {
                group: hsmcl_public.cl_group.clone(),
                ek: hsmcl_public.cl_pub_key.clone(),
                encrypted_secret_share: hsmcl_public.encrypted_share.clone(),
            })
        } else {
            Err(ProofError)
        }
    }
}

impl EphKeyGenFirstMsg {
    pub fn create_commitments() -> (EphKeyGenFirstMsg, EphCommWitness, EphEcKeyPair) {
        let base = Point::generator();

        let secret_share = Scalar::<Secp256k1>::random();

        let public_share = base * &secret_share;

        let h = Point::base_point2();
        let w = ECDDHWitness {
            x: secret_share.clone(),
        };
        let c = h * &secret_share;
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
        party_two_public: Party2Public,
        local_share: &Party2Private,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &Point<Secp256k1>,
        message: &BigInt,
    ) -> PartialSig {
        let q = Scalar::<Secp256k1>::group_order();
        //compute r = k2* R1
        let r: Point<Secp256k1> =
            ephemeral_other_public_share * &ephemeral_local_share.secret_share;

        let rx = r.x_coord().unwrap().mod_floor(q);
        let k2 = &ephemeral_local_share.secret_share.to_bigint();
        let k2_inv = BigInt::mod_inv(k2, q).unwrap();
        let k2_inv_m = BigInt::mod_mul(&k2_inv, message, q);
        let k2_inv_m_fe = Scalar::<Secp256k1>::from(&k2_inv_m);
        let c1 = encrypt(&party_two_public.group, &party_two_public.ek, &k2_inv_m_fe);
        let v = BigInt::mod_mul(&k2_inv, &local_share.x2.to_bigint(), q);
        let v = BigInt::mod_mul(&v, &rx, q);

        let c2 = eval_scal(&party_two_public.encrypted_secret_share, &v);
        let c3 = eval_sum(&c1.0, &c2);

        //c3:
        PartialSig { c3 }
    }
}
