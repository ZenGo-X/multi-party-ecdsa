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
use std::ops::Shl;

use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::FE;
use curv::GE;
use paillier::Paillier;
use paillier::{Add, Encrypt, Mul};
use paillier::{EncryptionKey, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::{
    CorrectKeyProofError, NICorrectKeyProof, RangeProofError, RangeProofNi,
};

use super::party_one::EphKeyGenFirstMsg as Party1EphKeyGenFirstMsg;
use super::party_one::KeyGenFirstMsg as Party1KeyGenFirstMessage;
use super::party_one::KeyGenSecondMsg as Party1KeyGenSecondMessage;
use super::party_one::PDLFirstMessage as Party1PDLFirstMessage;
use super::party_one::PDLSecondMessage as Party1PDLSecondMessage;
use super::SECURITY_BITS;
use crate::protocols::multi_party_ecdsa::gg_2018::mta::{MessageA, MessageB};

use zeroize::Zeroize;

const PAILLIER_KEY_SIZE: usize = 2048;
//****************** Begin: Party Two structs ******************//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub d_log_proof: DLogProof,
    pub public_share: GE,
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
    x2: FE,
}
#[derive(Debug)]
pub struct PDLchallenge {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
    a: BigInt,
    b: BigInt,
    blindness: BigInt,
    q_tag: GE,
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
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphCommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: ECDDHProof,
    pub c: GE, //c = secret_share * base_point2
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
        let base: GE = ECPoint::generator();
        let mut secret_share: FE = ECScalar::new_random();
        let public_share = base * secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        secret_share.zeroize();
        (
            KeyGenFirstMsg {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }

    pub fn create_with_fixed_secret_share(mut secret_share: FE) -> (KeyGenFirstMsg, EcKeyPair) {
        let base: GE = ECPoint::generator();
        let public_share = base * secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        secret_share.zeroize();
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
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_public_share.bytes_compressed_to_big_int(),
                &party_one_pk_commitment_blind_factor,
            )
        {
            flag = flag
        } else {
            flag = false
        };
        if party_one_zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_d_log_proof
                    .pk_t_rand_commitment
                    .bytes_compressed_to_big_int(),
                &party_one_zk_pok_blind_factor,
            )
        {
            flag = flag
        } else {
            flag = false
        };
        assert!(flag);
        DLogProof::verify(&party_one_d_log_proof)?;
        Ok(KeyGenSecondMsg {})
    }
}

pub fn compute_pubkey(local_share: &EcKeyPair, other_share_public_share: &GE) -> GE {
    let pubkey = other_share_public_share;
    pubkey.scalar_mul(&local_share.secret_share.get_element())
}

impl Party2Private {
    pub fn set_private_key(ec_key: &EcKeyPair) -> Party2Private {
        Party2Private {
            x2: ec_key.secret_share,
        }
    }

    pub fn update_private_key(party_two_private: &Party2Private, factor: &BigInt) -> Party2Private {
        let factor_fe: FE = ECScalar::from(factor);
        Party2Private {
            x2: party_two_private.x2.mul(&factor_fe.get_element()),
        }
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: usize,
        num_of_segments: usize,
        pub_ke_y: &GE,
        g: &GE,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.x2, &segment_size, num_of_segments, pub_ke_y, g)
    }

    // used to transform lindell master key to gg18 master key
    pub fn to_mta_message_b(&self, ek: &EncryptionKey, ciphertext: &BigInt) -> (MessageB, FE) {
        let message_a = MessageA {
            c: ciphertext.clone(),
        };
        MessageB::b(&self.x2, &ek, message_a)
    }
}

impl PaillierPublic {
    pub fn pdl_challenge(&self, other_share_public_share: &GE) -> (PDLFirstMessage, PDLchallenge) {
        let a_fe: FE = ECScalar::new_random();
        let a = a_fe.to_big_int();
        let q = FE::q();
        let q_sq = q.pow(2);
        let b = BigInt::sample_below(&q_sq);
        let b_fe: FE = ECScalar::from(&b);
        let b_enc = Paillier::encrypt(&self.ek, RawPlaintext::from(b.clone()));
        let ac = Paillier::mul(
            &self.ek,
            RawCiphertext::from(self.encrypted_secret_share.clone()),
            RawPlaintext::from(a.clone()),
        );
        let c_tag = Paillier::add(&self.ek, ac, b_enc).0.into_owned();
        let ab_concat = a.clone() + b.clone().shl(a.bit_length());
        let blindness = BigInt::sample_below(&q);
        let c_tag_tag =
            HashCommitment::create_commitment_with_user_defined_randomness(&ab_concat, &blindness);
        let g: GE = ECPoint::generator();
        let q_tag = other_share_public_share * &a_fe + g * b_fe;

        (
            PDLFirstMessage {
                c_tag: c_tag.clone(),
                c_tag_tag: c_tag_tag.clone(),
            },
            PDLchallenge {
                c_tag,
                c_tag_tag,
                a,
                b,
                blindness,
                q_tag,
            },
        )
    }

    pub fn pdl_decommit_c_tag_tag(pdl_chal: &PDLchallenge) -> PDLSecondMessage {
        let decommit = PDLdecommit {
            a: pdl_chal.a.clone(),
            b: pdl_chal.b.clone(),
            blindness: pdl_chal.blindness.clone(),
        };
        PDLSecondMessage { decommit }
    }

    pub fn verify_pdl(
        pdl_chal: &PDLchallenge,
        party_one_pdl_first_message: &Party1PDLFirstMessage,
        party_one_pdl_second_message: &Party1PDLSecondMessage,
    ) -> Result<(), ()> {
        let c_hat = party_one_pdl_first_message.c_hat.clone();
        let q_hat = party_one_pdl_second_message.decommit.q_hat;
        let blindness = party_one_pdl_second_message.decommit.blindness.clone();
        let c_hat_test = HashCommitment::create_commitment_with_user_defined_randomness(
            &q_hat.bytes_compressed_to_big_int(),
            &blindness,
        );
        if c_hat.clone() == c_hat_test && q_hat.get_element() == pdl_chal.q_tag.get_element() {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn verify_range_proof(
        paillier_context: &PaillierPublic,
        range_proof: &RangeProofNi,
    ) -> Result<(), RangeProofError> {
        range_proof.verify(
            &paillier_context.ek,
            &paillier_context.encrypted_secret_share,
        )
    }

    pub fn verify_ni_proof_correct_key(
        proof: NICorrectKeyProof,
        ek: &EncryptionKey,
    ) -> Result<(), CorrectKeyProofError> {
        //
        if ek.n.bit_length() < PAILLIER_KEY_SIZE - 1 {
            return Err(CorrectKeyProofError);
        };
        proof.verify(&ek)
    }
}

impl EphKeyGenFirstMsg {
    pub fn create_commitments() -> (EphKeyGenFirstMsg, EphCommWitness, EphEcKeyPair) {
        let base: GE = ECPoint::generator();

        let mut secret_share: FE = ECScalar::new_random();

        let public_share = base.scalar_mul(&secret_share.get_element());

        let h: GE = GE::base_point2();

        let c = &h * &secret_share;
        let mut x = secret_share;
        let w = ECDDHWitness { x };
        let delta = ECDDHStatement {
            g1: base,
            h1: public_share,
            g2: h,
            h2: c,
        };
        let d_log_proof = ECDDHProof::prove(&w, &delta);

        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &HSha256::create_hash_from_ge(&[&d_log_proof.a1, &d_log_proof.a2]).to_big_int(),
            &zk_pok_blind_factor,
        );

        let ec_key_pair = EphEcKeyPair {
            public_share,
            secret_share,
        };
        secret_share.zeroize();
        x.zeroize();
        (
            EphKeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            EphCommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share,
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
            g1: GE::generator(),
            h1: party_one_first_message.public_share,
            g2: GE::base_point2(),
            h2: party_one_first_message.c,
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
        ephemeral_other_public_share: &GE,
        message: &BigInt,
    ) -> PartialSig {
        let q = FE::q();
        //compute r = k2* R1
        let r = ephemeral_other_public_share
            .scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().unwrap().mod_floor(&q);
        let rho = BigInt::sample_below(&q.pow(2));
        let mut k2_inv = ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&q)
            .unwrap();
        let partial_sig = rho * &q + BigInt::mod_mul(&k2_inv, message, &q);

        let c1 = Paillier::encrypt(ek, RawPlaintext::from(partial_sig));
        let v = BigInt::mod_mul(
            &k2_inv,
            &BigInt::mod_mul(&rx, &local_share.x2.to_big_int(), &q),
            &q,
        );
        k2_inv.zeroize_bn();
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
