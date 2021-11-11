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
use paillier::{Decrypt, EncryptWithChosenRandomness, KeyGeneration};
use paillier::{DecryptionKey, EncryptionKey, Randomness, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zk_paillier::zkproofs::NiCorrectKeyProof;

use super::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMessage;
use super::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMessage;
use super::SECURITY_BITS;

use crate::utilities::mta::MessageB;
use crate::Error;

use crate::utilities::zk_pdl_with_slack::PDLwSlackProof;
use crate::utilities::zk_pdl_with_slack::PDLwSlackStatement;
use crate::utilities::zk_pdl_with_slack::PDLwSlackWitness;
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

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
    x1: Scalar<Secp256k1>,
    paillier_priv: DecryptionKey,
    c_key_randomness: BigInt,
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

        let public_share = base * &secret_share;

        let d_log_proof = DLogProof::<Secp256k1, Sha256>::prove(&secret_share);
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

        let d_log_proof = DLogProof::<Secp256k1, Sha256>::prove(&secret_share);

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
    pub fn set_private_key(ec_key: &EcKeyPair, paillier_key: &PaillierKeyPair) -> Party1Private {
        Party1Private {
            x1: ec_key.secret_share.clone(),
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
        NiCorrectKeyProof,
        PDLwSlackStatement,
        PDLwSlackProof,
        CompositeDLogProof,
    ) {
        let (ek_new, dk_new) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek_new);
        let factor_fe = Scalar::<Secp256k1>::from(&*factor);
        let x1_new = &party_one_private.x1 * factor_fe;
        let c_key_new = Paillier::encrypt_with_chosen_randomness(
            &ek_new,
            RawPlaintext::from(x1_new.to_bigint()),
            &randomness,
        )
        .0
        .into_owned();
        let correct_key_proof_new = NiCorrectKeyProof::proof(&dk_new, None);

        let paillier_key_pair = PaillierKeyPair {
            ek: ek_new.clone(),
            dk: dk_new.clone(),
            encrypted_share: c_key_new.clone(),
            randomness: randomness.0.clone(),
        };

        let party_one_private_new = Party1Private {
            x1: x1_new,
            paillier_priv: dk_new,
            c_key_randomness: randomness.0,
        };

        let (pdl_statement, pdl_proof, composite_dlog_proof) =
            PaillierKeyPair::pdl_proof(&party_one_private_new, &paillier_key_pair);

        (
            ek_new,
            c_key_new,
            party_one_private_new,
            correct_key_proof_new,
            pdl_statement,
            pdl_proof,
            composite_dlog_proof,
        )
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: usize,
        num_of_segments: usize,
        pub_ke_y: &Point<Secp256k1>,
        g: &Point<Secp256k1>,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.x1, &segment_size, num_of_segments, pub_ke_y, g)
    }

    // used to transform lindell master key to gg18 master key
    pub fn to_mta_message_b(
        &self,
        message_b: MessageB,
    ) -> Result<(Scalar<Secp256k1>, BigInt), Error> {
        message_b.verify_proofs_get_alpha(&self.paillier_priv, &self.x1)
    }
}

impl PaillierKeyPair {
    pub fn generate_keypair_and_encrypted_share(keygen: &EcKeyPair) -> PaillierKeyPair {
        let (ek, dk) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek);

        let encrypted_share = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(keygen.secret_share.to_bigint()),
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
            RawPlaintext::from(keygen.secret_share.to_bigint()),
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

    pub fn generate_ni_proof_correct_key(paillier_context: &PaillierKeyPair) -> NiCorrectKeyProof {
        NiCorrectKeyProof::proof(&paillier_context.dk, None)
    }

    pub fn pdl_proof(
        party1_private: &Party1Private,
        paillier_key_pair: &PaillierKeyPair,
    ) -> (PDLwSlackStatement, PDLwSlackProof, CompositeDLogProof) {
        let (n_tilde, h1, h2, xhi) = generate_h1_h2_n_tilde();
        let dlog_statement = DLogStatement {
            N: n_tilde,
            g: h1,
            ni: h2,
        };
        let composite_dlog_proof = CompositeDLogProof::prove(&dlog_statement, &xhi);

        // Generate PDL with slack statement, witness and proof
        let pdl_w_slack_statement = PDLwSlackStatement {
            ciphertext: paillier_key_pair.encrypted_share.clone(),
            ek: paillier_key_pair.ek.clone(),
            Q: Point::generator() * &party1_private.x1,
            G: Point::generator().to_point(),
            h1: dlog_statement.g.clone(),
            h2: dlog_statement.ni.clone(),
            N_tilde: dlog_statement.N,
        };

        let pdl_w_slack_witness = PDLwSlackWitness {
            x: party1_private.x1.clone(),
            r: party1_private.c_key_randomness.clone(),
        };

        let pdl_w_slack_proof = PDLwSlackProof::prove(&pdl_w_slack_witness, &pdl_w_slack_statement);
        (
            pdl_w_slack_statement,
            pdl_w_slack_proof,
            composite_dlog_proof,
        )
    }
}

impl EphKeyGenFirstMsg {
    pub fn create() -> (EphKeyGenFirstMsg, EphEcKeyPair) {
        let base = Point::generator();
        let secret_share = Scalar::<Secp256k1>::random();
        let public_share = &*base * &secret_share;
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
        party_one_private: &Party1Private,
        partial_sig_c3: &BigInt,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &Point<Secp256k1>,
    ) -> Signature {
        //compute r = k2* R1
        let r = ephemeral_other_public_share * &ephemeral_local_share.secret_share;

        let rx = r
            .x_coord()
            .unwrap()
            .mod_floor(Scalar::<Secp256k1>::group_order());

        let k1_inv = ephemeral_local_share.secret_share.invert().unwrap();

        let s_tag = Paillier::decrypt(
            &party_one_private.paillier_priv,
            &RawCiphertext::from(partial_sig_c3),
        )
        .0;
        let s_tag_fe = Scalar::<Secp256k1>::from(s_tag.as_ref());
        let s_tag_tag = s_tag_fe * k1_inv;
        let s_tag_tag_bn = s_tag_tag.to_bigint();

        let s = cmp::min(
            s_tag_tag_bn.clone(),
            Scalar::<Secp256k1>::group_order().clone() - s_tag_tag_bn,
        );

        Signature { s, r: rx }
    }

    pub fn compute_with_recid(
        party_one_private: &Party1Private,
        partial_sig_c3: &BigInt,
        ephemeral_local_share: &EphEcKeyPair,
        ephemeral_other_public_share: &Point<Secp256k1>,
    ) -> SignatureRecid {
        //compute r = k2* R1
        let r = ephemeral_other_public_share * &ephemeral_local_share.secret_share;

        let rx = r
            .x_coord()
            .unwrap()
            .mod_floor(Scalar::<Secp256k1>::group_order());
        let ry = r
            .y_coord()
            .unwrap()
            .mod_floor(Scalar::<Secp256k1>::group_order());
        let k1_inv = ephemeral_local_share.secret_share.invert().unwrap();

        let s_tag = Paillier::decrypt(
            &party_one_private.paillier_priv,
            &RawCiphertext::from(partial_sig_c3),
        )
        .0;
        let s_tag_fe = Scalar::<Secp256k1>::from(s_tag.as_ref());
        let s_tag_tag = s_tag_fe * k1_inv;
        let s_tag_tag_bn = s_tag_tag.to_bigint();
        let s = cmp::min(
            s_tag_tag_bn.clone(),
            Scalar::<Secp256k1>::group_order() - &s_tag_tag_bn,
        );

        /*
         Calculate recovery id - it is not possible to compute the public key out of the signature
         itself. Recovery id is used to enable extracting the public key uniquely.
         1. id = R.y & 1
         2. if (s > curve.q / 2) id = id ^ 1
        */
        let is_ry_odd = ry.test_bit(0);
        let mut recid = if is_ry_odd { 1 } else { 0 };
        if s_tag_tag_bn > Scalar::<Secp256k1>::group_order() - &s_tag_tag_bn {
            recid ^= 1;
        }

        SignatureRecid { s, r: rx, recid }
    }
}

pub fn verify(
    signature: &Signature,
    pubkey: &Point<Secp256k1>,
    message: &BigInt,
) -> Result<(), Error> {
    let s_fe = Scalar::<Secp256k1>::from(&signature.s);
    let rx_fe = Scalar::<Secp256k1>::from(&signature.r);

    let s_inv_fe = s_fe.invert().unwrap();
    let e_fe: Scalar<Secp256k1> =
        Scalar::<Secp256k1>::from(&message.mod_floor(Scalar::<Secp256k1>::group_order()));
    let u1 = Point::generator() * e_fe * &s_inv_fe;
    let u2 = &*pubkey * rx_fe * &s_inv_fe;

    // second condition is against malleability
    let rx_bytes = &BigInt::to_bytes(&signature.r)[..];
    let u1_plus_u2_bytes = &BigInt::to_bytes(&(u1 + u2).x_coord().unwrap())[..];

    if rx_bytes.ct_eq(u1_plus_u2_bytes).unwrap_u8() == 1
        && signature.s < Scalar::<Secp256k1>::group_order() - signature.s.clone()
    {
        Ok(())
    } else {
        Err(Error::InvalidSig)
    }
}

pub fn generate_h1_h2_n_tilde() -> (BigInt, BigInt, BigInt, BigInt) {
    //note, should be safe primes:
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();;
    let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
    let one = BigInt::one();
    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    let h1 = BigInt::sample_below(&phi);
    let s = BigInt::from(2).pow(256_u32);
    let xhi = BigInt::sample_below(&s);
    let h1_inv = BigInt::mod_inv(&h1, &ek_tilde.n).unwrap();
    let h2 = BigInt::mod_pow(&h1_inv, &xhi, &ek_tilde.n);

    (ek_tilde.n, h1, h2, xhi)
}
