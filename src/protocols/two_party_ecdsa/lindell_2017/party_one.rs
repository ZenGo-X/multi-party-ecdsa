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

use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use cryptography_utils::BigInt;
use cryptography_utils::GE;
use cryptography_utils::FE;

use super::party_two;
use super::structs::{Visibility, WBigInt, W, WPK, WSK};

//****************** Begin: Party One structs ******************//
#[derive(Debug)]
pub struct KeyGenFirstMsg {
    public_share: WPK,
    secret_share: WSK,

    pub pk_commitment: WBigInt,
    pk_commitment_blind_factor: WBigInt,
    pub zk_pok_commitment: WBigInt,
    zk_pok_blind_factor: WBigInt,
    d_log_proof: W<DLogProof>,
}

#[derive(Debug)]
pub struct KeyGenSecondMsg {
    pub pk_commitment_blind_factor: WBigInt,
    pub zk_pok_blind_factor: WBigInt,
    pub public_share: WPK,
    pub d_log_proof: W<DLogProof>,
}

#[derive(Debug)]
pub struct PaillierKeyPair {
    pub ek: W<EncryptionKey>,
    dk: W<DecryptionKey>,
    pub encrypted_share: WBigInt,
    randomness: WBigInt,
}

#[derive(Debug)]
pub struct Signature {
    pub s: WBigInt,
    pub r: WBigInt,
}

//****************** End: Party One structs ******************//

impl KeyGenFirstMsg {
    pub fn create_commitments() -> KeyGenFirstMsg {
        let base: GE = ECPoint::new();
        let sk: FE = ECScalar::new_random();
        //in Lindell's protocol range proof works only for x1<q/3
        let sk: FE = ECScalar::from_big_int(&sk.to_big_int().div_floor(&BigInt::from(3)));
        let pk = base.scalar_mul(&sk.get_element());

        let d_log_proof = DLogProof::prove( &sk);
        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.get_x_coor_as_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.get_x_coor_as_big_int(),
            &zk_pok_blind_factor,
        );

        KeyGenFirstMsg {
            public_share: WPK {
                val: pk,
                visibility: Visibility::Private,
            },
            secret_share: WSK {
                val: sk,
                visibility: Visibility::Private,
            },
            pk_commitment: WBigInt {
                val: pk_commitment,
                visibility: Visibility::Public,
            },

            pk_commitment_blind_factor: WBigInt {
                val: pk_commitment_blind_factor,
                visibility: Visibility::Private,
            },

            zk_pok_commitment: WBigInt {
                val: zk_pok_commitment,
                visibility: Visibility::Public,
            },

            zk_pok_blind_factor: WBigInt {
                val: zk_pok_blind_factor,
                visibility: Visibility::Private,
            },

            d_log_proof: W {
                val: d_log_proof,
                visibility: Visibility::Private,
            },
        }
    }
    pub fn create_commitments_with_fixed_secret_share( sk: FE) -> KeyGenFirstMsg {

        //in Lindell's protocol range proof works only for x1<q/3
        let sk_bigint = sk.to_big_int();
        assert!(&sk_bigint<&sk.get_q().div_floor(&BigInt::from(3)));
        let base: GE = ECPoint::new();
        let pk = base.scalar_mul(&sk.get_element());

        let d_log_proof = DLogProof::prove( &sk);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.get_x_coor_as_big_int(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.get_x_coor_as_big_int(),
            &zk_pok_blind_factor,
        );

        KeyGenFirstMsg {
            public_share: WPK {
                val: pk,
                visibility: Visibility::Private,
            },
            secret_share: WSK {
                val: sk,
                visibility: Visibility::Private,
            },
            pk_commitment: WBigInt {
                val: pk_commitment,
                visibility: Visibility::Public,
            },

            pk_commitment_blind_factor: WBigInt {
                val: pk_commitment_blind_factor,
                visibility: Visibility::Private,
            },

            zk_pok_commitment: WBigInt {
                val: zk_pok_commitment,
                visibility: Visibility::Public,
            },

            zk_pok_blind_factor: WBigInt {
                val: zk_pok_blind_factor,
                visibility: Visibility::Private,
            },

            d_log_proof: W {
                val: d_log_proof,
                visibility: Visibility::Private,
            },
        }
    }
}

impl KeyGenSecondMsg {
    pub fn verify_and_decommit(
        first_message: &KeyGenFirstMsg,
        proof: &DLogProof,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(proof)?;
        Ok(KeyGenSecondMsg {
            pk_commitment_blind_factor: WBigInt {
                val: first_message.pk_commitment_blind_factor.val.clone(),
                visibility: Visibility::Public,
            },

            zk_pok_blind_factor: WBigInt {
                val: first_message.zk_pok_blind_factor.val.clone(),
                visibility: Visibility::Public,
            },

            public_share: WPK {
                val: first_message.public_share.val.clone(),
                visibility: Visibility::Public,
            },

            d_log_proof: W {
                val: first_message.d_log_proof.val.clone(),
                visibility: Visibility::Public,
            },
        })
    }
}

pub fn compute_pubkey(
    local_share: &KeyGenFirstMsg,
    other_share: &party_two::KeyGenFirstMsg,
) -> GE {
    let mut pubkey = other_share.public_share.val.clone();
    pubkey.scalar_mul(&local_share.secret_share.val.get_element())
}

impl PaillierKeyPair {
    pub fn generate_keypair_and_encrypted_share(keygen: &KeyGenFirstMsg) -> PaillierKeyPair {
        let (ek, dk) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek);

        let encrypted_share = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(keygen.secret_share.val.to_big_int()),
            &randomness,
        ).0
        .into_owned();

        PaillierKeyPair {
            ek: W {
                val: ek,
                visibility: Visibility::Public,
            },
            dk: W {
                val: dk,
                visibility: Visibility::Private,
            },
            encrypted_share: WBigInt {
                val: encrypted_share,
                visibility: Visibility::Public,
            },
            randomness: WBigInt {
                val: randomness.0,
                visibility: Visibility::Private,
            },
        }
    }

    pub fn generate_range_proof(
        paillier_context: &PaillierKeyPair,
        keygen: &KeyGenFirstMsg,
    ) -> (W<EncryptedPairs>, W<ChallengeBits>, W<Proof>) {
        let temp : FE = ECScalar::new_random();
        let (encrypted_pairs, challenge, proof) = Paillier::prover(
            &paillier_context.ek.val,
            &temp.get_q(),
            &keygen.secret_share.val.to_big_int(),
            &paillier_context.randomness.val,
        );

        (
            W {
                val: encrypted_pairs,
                visibility: Visibility::Public,
            },
            W {
                val: challenge,
                visibility: Visibility::Public,
            },
            W {
                val: proof,
                visibility: Visibility::Public,
            },
        )
    }

    pub fn generate_proof_correct_key(
        paillier_context: &PaillierKeyPair,
        challenge: &Challenge,
    ) -> Result<W<CorrectKeyProof>, CorrectKeyProofError> {
        Ok(W {
            val: Paillier::prove(&paillier_context.dk.val, challenge).unwrap(),
            visibility: Visibility::Public,
        })
    }
}

impl Signature {
    pub fn compute(
        keypair: &PaillierKeyPair,
        partial_sig: &party_two::PartialSig,
        ephemeral_local_share: &KeyGenFirstMsg,
        ephemeral_other_public_share: &WPK,
    ) -> Signature {
        //compute r = k2* R1
        let temp : FE = ECScalar::new_random();
        let mut r = ephemeral_other_public_share.val.clone();
        let r = r.scalar_mul(&ephemeral_local_share.secret_share.val.get_element());
        let rx = r.get_x_coor_as_big_int().mod_floor(&temp.get_q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .val
            .to_big_int()
            .invert(&temp.get_q())
            .unwrap();
        let s_tag = Paillier::decrypt(&keypair.dk.val, &RawCiphertext::from(&partial_sig.c3.val));
        let s_tag_tag = BigInt::mod_mul(&k1_inv, &s_tag.0, &temp.get_q());
        let s = cmp::min(s_tag_tag.clone(), &temp.get_q().clone() - s_tag_tag.clone());

        Signature {
            s: WBigInt {
                val: s,
                visibility: Visibility::Public,
            },
            r: WBigInt {
                val: rx,
                visibility: Visibility::Public,
            },
        }
    }
}

pub fn verify(
    signature: &Signature,
    pubkey: &GE,
    message: &BigInt,
) -> Result<(), ProofError> {
    let temp : FE = ECScalar::new_random();
    let b = signature
        .s
        .val
        .invert(&temp.get_q())
        .unwrap()
        .mod_floor(&temp.get_q());
    let a = message.mod_floor(&temp.get_q());
    let u1 = BigInt::mod_mul(&a, &b, &temp.get_q());
    let u2 = BigInt::mod_mul(&signature.r.val, &b, &temp.get_q());
    // can be faster using shamir trick
    let mut point1: GE = ECPoint::new();
    let u1_fe: FE = ECScalar::from_big_int(&u1);
    let u2_fe: FE = ECScalar::from_big_int(&u2);
    let point1 = point1.scalar_mul(&u1_fe.get_element());


    let mut point2 = pubkey;
    let point2 = point2.clone();
    let point2 = point2.scalar_mul(&u2_fe.get_element());

    if signature.r.val == point1.add_point( &point2.get_element()).get_x_coor_as_big_int() {
        Ok(())
    } else {
        Err(ProofError)
    }
}
