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
use paillier::{Decrypt, EncryptWithChosenRandomness, KeyGeneration};
use paillier::{DecryptionKey, EncryptionKey, Randomness, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi};

use super::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMessage;
use super::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMessage;
use super::party_two::PDLFirstMessage as Party2PDLFirstMessage;
use super::party_two::PDLSecondMessage as Party2PDLSecondMessage;
use super::SECURITY_BITS;

use crate::protocols::multi_party_ecdsa::gg_2018::mta::MessageB;
use crate::Error;

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
    pub d_log_proof: DLogProof,
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
pub struct PaillierKeyPair {
    pub ek: EncryptionKey,
    dk: DecryptionKey,
    pub encrypted_share: BigInt,
    randomness: BigInt,
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
    paillier_priv: DecryptionKey,
    c_key_randomness: BigInt,
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
    pub d_log_proof: ECDDHProof,
    pub public_share: GE,
    pub c: GE, //c = secret_share * base_point2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenSecondMsg {}

//****************** End: Party One structs ******************//

impl KeyGenFirstMsg {
    pub fn create_commitments() -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base: GE = ECPoint::generator();

        let mut scalar: FE = ECScalar::new_random();
        //in Lindell's protocol range proof works only for x1<q/3
        let mut secret_share: FE = ECScalar::from(&scalar.to_big_int().div_floor(&BigInt::from(3)));
        scalar.zeroize();

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
        secret_share.zeroize();
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share,
                d_log_proof,
            },
            ec_key_pair,
        )
    }

    pub fn create_commitments_with_fixed_secret_share(
        mut secret_share: FE,
    ) -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        //in Lindell's protocol range proof works only for x1<q/3
        let sk_bigint = secret_share.to_big_int();
        let q_third = FE::q();
        assert!(sk_bigint < q_third.div_floor(&BigInt::from(3)));
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
        secret_share.zeroize();
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share,
                d_log_proof,
            },
            ec_key_pair,
        )
    }
}

impl KeyGenSecondMsg {
    pub fn verify_and_decommit(
        comm_witness: CommWitness,
        proof: &DLogProof,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(proof)?;
        Ok(KeyGenSecondMsg { comm_witness })
    }
}

pub fn compute_pubkey(party_one_private: &Party1Private, other_share_public_share: &GE) -> GE {
    other_share_public_share * &party_one_private.x1
}

impl Party1Private {
    pub fn set_private_key(ec_key: &EcKeyPair, paillier_key: &PaillierKeyPair) -> Party1Private {
        Party1Private {
            x1: ec_key.secret_share,
            paillier_priv: paillier_key.dk.clone(),
            c_key_randomness: paillier_key.randomness.clone(),
        }
    }
    pub fn refresh_private_key(
        party_one_private: &Party1Private,
        factor: &BigInt,
    ) -> (
        EncryptionKey,
        BigInt,
        Party1Private,
        NICorrectKeyProof,
        RangeProofNi,
    ) {
        let (ek_new, dk_new) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek_new);
        let factor_fe: FE = ECScalar::from(&factor);
        let x1_new = party_one_private.x1 * factor_fe;
        let three = BigInt::from(3);
        let c_key_new = Paillier::encrypt_with_chosen_randomness(
            &ek_new,
            RawPlaintext::from(x1_new.to_big_int().clone()),
            &randomness,
        )
        .0
        .into_owned();
        let correct_key_proof_new = NICorrectKeyProof::proof(&dk_new);

        let range_proof_new = RangeProofNi::prove(
            &ek_new,
            &(FE::q() * three.clone()),
            &c_key_new,
            &x1_new.to_big_int(),
            &randomness.0,
        );

        let party_one_private_new = Party1Private {
            x1: x1_new,
            paillier_priv: dk_new.clone(),
            c_key_randomness: randomness.0,
        };

        (
            ek_new,
            c_key_new,
            party_one_private_new,
            correct_key_proof_new,
            range_proof_new,
        )
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: usize,
        num_of_segments: usize,
        pub_ke_y: &GE,
        g: &GE,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.x1, &segment_size, num_of_segments, pub_ke_y, g)
    }

    // used to transform lindell master key to gg18 master key
    pub fn to_mta_message_b(&self, message_b: MessageB) -> Result<FE, Error> {
        message_b.verify_proofs_get_alpha(&self.paillier_priv, &self.x1)
    }
}

impl PaillierKeyPair {
    pub fn generate_keypair_and_encrypted_share(keygen: &EcKeyPair) -> PaillierKeyPair {
        let (ek, dk) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek);

        let encrypted_share = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(keygen.secret_share.to_big_int()),
            &randomness,
        )
        .0
        .into_owned();

        PaillierKeyPair {
            ek,
            dk,
            encrypted_share,
            randomness: randomness.0,
        }
    }

    pub fn generate_encrypted_share_from_fixed_paillier_keypair(
        ek: &EncryptionKey,
        dk: &DecryptionKey,
        keygen: &EcKeyPair,
    ) -> PaillierKeyPair {
        let randomness = Randomness::sample(ek);

        let encrypted_share = Paillier::encrypt_with_chosen_randomness(
            ek,
            RawPlaintext::from(keygen.secret_share.to_big_int()),
            &randomness,
        )
        .0
        .into_owned();

        PaillierKeyPair {
            ek: ek.clone(),
            dk: dk.clone(),
            encrypted_share,
            randomness: randomness.0,
        }
    }

    pub fn generate_range_proof(
        paillier_context: &PaillierKeyPair,
        party_one_private: &Party1Private,
    ) -> RangeProofNi {
        RangeProofNi::prove(
            &paillier_context.ek,
            &FE::q(),
            &paillier_context.encrypted_share.clone(),
            &party_one_private.x1.to_big_int(),
            &paillier_context.randomness,
        )
    }

    pub fn generate_ni_proof_correct_key(paillier_context: &PaillierKeyPair) -> NICorrectKeyProof {
        NICorrectKeyProof::proof(&paillier_context.dk)
    }

    pub fn pdl_first_stage(
        party_one_private: &Party1Private,
        pdl_first_message: &Party2PDLFirstMessage,
    ) -> (PDLFirstMessage, PDLdecommit, BigInt) {
        let c_tag = pdl_first_message.c_tag.clone();
        let alpha = Paillier::decrypt(
            &party_one_private.paillier_priv.clone(),
            &RawCiphertext::from(c_tag.clone()),
        );
        let alpha_fe: FE = ECScalar::from(&alpha.0);
        let g: GE = ECPoint::generator();
        let q_hat = g * alpha_fe;
        let blindness = BigInt::sample_below(&FE::q());
        let c_hat = HashCommitment::create_commitment_with_user_defined_randomness(
            &q_hat.bytes_compressed_to_big_int(),
            &blindness,
        );
        (
            PDLFirstMessage { c_hat },
            PDLdecommit { blindness, q_hat },
            alpha.0.into_owned(),
        )
    }

    pub fn pdl_second_stage(
        pdl_party_two_first_message: &Party2PDLFirstMessage,
        pdl_party_two_second_message: &Party2PDLSecondMessage,
        party_one_private: Party1Private,
        pdl_decommit: PDLdecommit,
        alpha: BigInt,
    ) -> Result<PDLSecondMessage, ()> {
        let a = pdl_party_two_second_message.decommit.a.clone();
        let b = pdl_party_two_second_message.decommit.b.clone();
        let blindness = pdl_party_two_second_message.decommit.blindness.clone();

        let ab_concat = a.clone() + b.clone().shl(a.bit_length()); // b|a (in the paper it is a|b)
        let c_tag_tag_test =
            HashCommitment::create_commitment_with_user_defined_randomness(&ab_concat, &blindness);
        let ax1 = a.clone() * party_one_private.x1.to_big_int();
        let alpha_test = ax1 + b.clone();
        if alpha_test == alpha && pdl_party_two_first_message.c_tag_tag.clone() == c_tag_tag_test {
            Ok(PDLSecondMessage {
                decommit: pdl_decommit,
            })
        } else {
            Err(())
        }
    }
}

impl EphKeyGenFirstMsg {
    pub fn create() -> (EphKeyGenFirstMsg, EphEcKeyPair) {
        let base: GE = ECPoint::generator();
        let mut secret_share: FE = ECScalar::new_random();
        let public_share = &base * &secret_share;
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
        let ec_key_pair = EphEcKeyPair {
            public_share,
            secret_share,
        };
        secret_share.zeroize();
        x.zeroize();
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
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_two_public_share.bytes_compressed_to_big_int(),
                &party_two_pk_commitment_blind_factor,
            )
        {
            flag = flag
        } else {
            flag = false
        };
        if party_two_zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &HSha256::create_hash_from_ge(&[
                    &party_two_d_log_proof.a1,
                    &party_two_d_log_proof.a2,
                ])
                .to_big_int(),
                &party_two_zk_pok_blind_factor,
            )
        {
            flag = flag
        } else {
            flag = false
        };
        assert!(flag);
        let delta = ECDDHStatement {
            g1: GE::generator(),
            h1: *party_two_public_share,
            g2: GE::base_point2(),
            h2: party_two_second_message.comm_witness.c,
        };
        party_two_d_log_proof.verify(&delta)?;
        Ok(EphKeyGenSecondMsg {})
    }
}

impl Signature {
    pub fn compute(
        party_one_private: &Party1Private,
        partial_sig_c3: &BigInt,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &GE,
    ) -> Signature {
        //compute r = k2* R1
        let r = ephemeral_other_public_share
            .scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().unwrap().mod_floor(&FE::q());

        let mut k1_inv = ephemeral_local_share.secret_share.invert();

        let s_tag = Paillier::decrypt(
            &party_one_private.paillier_priv,
            &RawCiphertext::from(partial_sig_c3),
        )
        .0;
        let mut s_tag_fe: FE = ECScalar::from(&s_tag);
        let s_tag_tag = s_tag_fe * k1_inv;
        k1_inv.zeroize();
        s_tag_fe.zeroize();
        let s_tag_tag_bn = s_tag_tag.to_big_int();

        let s = cmp::min(s_tag_tag_bn.clone(), FE::q().clone() - s_tag_tag_bn.clone());

        Signature { s, r: rx }
    }

    pub fn compute_with_recid(
        party_one_private: &Party1Private,
        partial_sig_c3: &BigInt,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &GE,
    ) -> SignatureRecid {
        //compute r = k2* R1
        let r = ephemeral_other_public_share
            .scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().unwrap().mod_floor(&FE::q());
        let ry = r.y_coor().unwrap().mod_floor(&FE::q());
        let mut k1_inv = ephemeral_local_share.secret_share.invert();

        let s_tag = Paillier::decrypt(
            &party_one_private.paillier_priv,
            &RawCiphertext::from(partial_sig_c3),
        )
        .0;
        let mut s_tag_fe: FE = ECScalar::from(&s_tag);
        let s_tag_tag = s_tag_fe * k1_inv;
        k1_inv.zeroize();
        s_tag_fe.zeroize();
        let s_tag_tag_bn = s_tag_tag.to_big_int();
        let s = cmp::min(s_tag_tag_bn.clone(), FE::q().clone() - s_tag_tag_bn.clone());

        /*
         Calculate recovery id - it is not possible to compute the public key out of the signature
         itself. Recovery id is used to enable extracting the public key uniquely.
         1. id = R.y & 1
         2. if (s > curve.q / 2) id = id ^ 1
        */
        let is_ry_odd = ry.tstbit(0);
        let mut recid = if is_ry_odd { 1 } else { 0 };
        if s_tag_tag_bn.clone() > FE::q() - s_tag_tag_bn.clone() {
            recid = recid ^ 1;
        }

        SignatureRecid { s, r: rx, recid }
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
    let rx_bytes = &BigInt::to_vec(&signature.r)[..];
    let u1_plus_u2_bytes = &BigInt::to_vec(&(u1 + u2).x_coor().unwrap())[..];

    if rx_bytes.ct_eq(&u1_plus_u2_bytes).unwrap_u8() == 1
        && signature.s < FE::q() - signature.s.clone()
    {
        Ok(())
    } else {
        Err(Error::InvalidSig)
    }
}
