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

use curv::arithmetic::*;
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
use subtle::ConstantTimeEq;

use super::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMessage;
use super::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMessage;
use super::SECURITY_BITS;
use crate::Error::{self, InvalidSig};

//****************** Begin: Party One structs ******************//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: Point<Secp256k1>,
    secret_share: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: Point<Secp256k1>,
    pub d_log_proof: DLogProof<Secp256k1, Sha256>,
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
    x1: Scalar<Secp256k1>,
    hsmcl_pub: PK,
    hsmcl_priv: SK,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLFirstMessage {
    pub c_hat: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLdecommit {
    pub q_hat: Point<Secp256k1>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenFirstMsg {
    pub d_log_proof: ECDDHProof<Secp256k1, Sha256>,
    pub public_share: Point<Secp256k1>,
    pub c: Point<Secp256k1>, //c = secret_share * base_point2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenSecondMsg {}

//****************** End: Party One structs ******************//

impl KeyGenFirstMsg {
    pub fn create_commitments() -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base = Point::generator();

        let secret_share = Scalar::<Secp256k1>::random();
        //in Lindell's protocol range proof works only for x1<q/3
        let secret_share: Scalar<Secp256k1> =
            Scalar::<Secp256k1>::from(&secret_share.to_bigint().div_floor(&BigInt::from(3)));

        let public_share = base * &secret_share;

        let d_log_proof = DLogProof::prove(&secret_share);
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
                &BigInt::from_bytes(d_log_proof.pk_t_rand_commitment.to_bytes(true).as_ref()),
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
        secret_share: Scalar<Secp256k1>,
    ) -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base = Point::generator();
        let public_share = base * &secret_share;

        let d_log_proof = DLogProof::prove(&secret_share);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(public_share.to_bytes(true).as_ref()),
                &pk_commitment_blind_factor,
            );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(d_log_proof.pk_t_rand_commitment.to_bytes(true).as_ref()),
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
        proof: &DLogProof<Secp256k1, Sha256>,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(proof)?;
        Ok(KeyGenSecondMsg { comm_witness })
    }
}

pub fn compute_pubkey(
    party_one_private: &Party1Private,
    other_share_public_share: &Point<Secp256k1>,
) -> Point<Secp256k1> {
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
        let cl_group = CLGroup::new_from_setup(&1348, seed);
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
                secret: secret_key,
                encrypted_share: ciphertext.clone(),
            },
            HSMCLPublic {
                cl_pub_key: public_key,
                proof,
                encrypted_share: ciphertext,
                cl_group,
            },
        )
    }
}

impl EphKeyGenFirstMsg {
    pub fn create() -> (EphKeyGenFirstMsg, EphEcKeyPair) {
        let base = Point::generator();
        let secret_share = Scalar::<Secp256k1>::random();
        let public_share = base * &secret_share;
        let h = Point::<Secp256k1>::base_point2();
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
        if party_two_pk_commitment
            != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(party_two_public_share.to_bytes(true).as_ref()),
                party_two_pk_commitment_blind_factor,
            )
        {
            flag = false
        }
        if party_two_zk_pok_commitment
            != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &Sha256::new()
                    .chain_points([&party_two_d_log_proof.a1, &party_two_d_log_proof.a2])
                    .result_bigint(),
                party_two_zk_pok_blind_factor,
            )
        {
            flag = false
        }
        if !flag {
            return Err(ProofError);
        }
        let delta = ECDDHStatement {
            g1: Point::generator().to_point(),
            h1: party_two_public_share.clone(),
            g2: Point::<Secp256k1>::base_point2().clone(),
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
        ephemeral_other_public_share: &Point<Secp256k1>,
    ) -> Signature {
        //compute r = k2* R1
        let r = ephemeral_other_public_share * &ephemeral_local_share.secret_share;

        let rx = r
            .x_coord()
            .unwrap()
            .mod_floor(Scalar::<Secp256k1>::group_order());
        let k1 = &ephemeral_local_share.secret_share.to_bigint();
        let k1_inv = BigInt::mod_inv(k1, Scalar::<Secp256k1>::group_order()).unwrap();
        let s_tag = decrypt(
            &hsmcl.cl_group,
            &party_one_private.hsmcl_priv,
            &partial_sig_c3,
        );
        let s_tag_tag = BigInt::mod_mul(
            &k1_inv,
            &s_tag.to_bigint(),
            Scalar::<Secp256k1>::group_order(),
        );
        let s = cmp::min(
            s_tag_tag.clone(),
            Scalar::<Secp256k1>::group_order().clone() - s_tag_tag,
        );
        Signature { s, r: rx }
    }
}

pub fn verify(
    signature: &Signature,
    pubkey: &Point<Secp256k1>,
    message: &BigInt,
) -> Result<(), Error> {
    let s_fe = Scalar::<Secp256k1>::from(&signature.s);
    let rx_fe = Scalar::<Secp256k1>::from(&signature.r);

    let s_inv_fe = s_fe.invert().ok_or(Error::InvalidSig)?;
    let e_fe: Scalar<Secp256k1> =
        Scalar::<Secp256k1>::from(&message.mod_floor(Scalar::<Secp256k1>::group_order()));
    let u1 = Point::generator() * e_fe * &s_inv_fe;
    let u2 = pubkey * rx_fe * &s_inv_fe;

    // second condition is against malleability
    let rx_bytes = &BigInt::to_bytes(&signature.r)[..];
    let u1_plus_u2_bytes = &BigInt::to_bytes(&(u1 + u2).x_coord().unwrap())[..];

    if rx_bytes.ct_eq(u1_plus_u2_bytes).unwrap_u8() == 1
        && signature.s < Scalar::<Secp256k1>::group_order() - signature.s.clone()
    {
        Ok(())
    } else {
        Err(InvalidSig)
    }
}
