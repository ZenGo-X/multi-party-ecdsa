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
use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::BigInt;
use cryptography_utils::GE;
use cryptography_utils::FE;

use paillier::*;

use super::structs::{Visibility, WBigInt, W, WPK, WSK};

//****************** Begin: Party Two structs ******************//

#[derive(Debug)]
pub struct KeyGenFirstMsg {
    pub d_log_proof: W<DLogProof>,
    pub public_share: WPK,
    secret_share: WSK,
}

#[derive(Debug)]
pub struct KeyGenSecondMsg {}

#[derive(Debug)]
pub struct PaillierPublic {
    pub ek: W<EncryptionKey>,
    pub encrypted_secret_share: WBigInt,
}

#[derive(Debug)]
pub struct PartialSig {
    pub c3: WBigInt,
}

//****************** End: Party Two structs ******************//

impl KeyGenFirstMsg {
    pub fn create() -> KeyGenFirstMsg {
        let base: GE = ECPoint::new();
        let sk: FE = ECScalar::new_random();
        let pk = base.scalar_mul(&sk.get_element());

        KeyGenFirstMsg {
            d_log_proof: W {
                val: DLogProof::prove( &sk),
                visibility: Visibility::Public,
            },

            public_share: WPK {
                val: pk,
                visibility: Visibility::Public,
            },

            secret_share: WSK {
                val: sk,
                visibility: Visibility::Private,
            },
        }
    }

    pub fn create_with_fixed_secret_share( sk: FE) -> KeyGenFirstMsg {
        let base: GE = ECPoint::new();
        let pk = base.scalar_mul(&sk.get_element());
        KeyGenFirstMsg {
            d_log_proof: W {
                val: DLogProof::prove( &sk),
                visibility: Visibility::Public,
            },

            public_share: WPK {
                val: pk,
                visibility: Visibility::Public,
            },

            secret_share: WSK {
                val: sk,
                visibility: Visibility::Private,
            },
        }
    }
}

impl KeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        party_one_pk_commitment: &WBigInt,
        party_one_zk_pok_commitment: &WBigInt,
        party_one_zk_pok_blind_factor: &WBigInt,
        party_one_public_share: &WPK,
        party_one_pk_commitment_blind_factor: &WBigInt,
        party_one_d_log_proof: &W<DLogProof>,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        let mut flag = true;
        match party_one_pk_commitment.val
            == HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_public_share.val.get_x_coor_as_big_int(),
                &party_one_pk_commitment_blind_factor.val,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_one_zk_pok_commitment.val
            == HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_d_log_proof.val.pk_t_rand_commitment.get_x_coor_as_big_int(),
                &party_one_zk_pok_blind_factor.val,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        DLogProof::verify(&party_one_d_log_proof.val)?;
        Ok(KeyGenSecondMsg {})
    }
}

impl PaillierPublic {
    pub fn verify_range_proof(
        paillier_context: &PaillierPublic,
        challenge: &W<ChallengeBits>,
        encrypted_pairs: &W<EncryptedPairs>,
        proof: &W<Proof>,
    ) -> bool {
        let temp : FE = ECScalar::new_random();
        Paillier::verifier(
            &paillier_context.ek.val,
            &challenge.val,
            &encrypted_pairs.val,
            &proof.val,
            &temp.get_q(),
            RawCiphertext::from(&paillier_context.encrypted_secret_share.val),
        ).is_ok()
    }
    pub fn generate_correct_key_challenge(
        paillier_context: &PaillierPublic,
    ) -> (W<Challenge>, W<VerificationAid>) {
        let (challenge, verification_aid) = Paillier::challenge(&paillier_context.ek.val);
        (
            W {
                val: challenge,
                visibility: Visibility::Public,
            },
            W {
                val: verification_aid,
                visibility: Visibility::Private,
            },
        )
    }

    pub fn verify_correct_key(
        proof: &W<CorrectKeyProof>,
        aid: &W<VerificationAid>,
    ) -> Result<(), CorrectKeyProofError> {
        Paillier::verify(&proof.val, &aid.val)
    }
}

impl PartialSig {
    pub fn compute(
        ek: &W<EncryptionKey>,
        encrypted_secret_share: &WBigInt,
        local_share: &KeyGenFirstMsg,
        ephemeral_local_share: &KeyGenFirstMsg,
        ephemeral_other_public_share: &WPK,
        message: &BigInt,
    ) -> PartialSig {
        let temp : FE = ECScalar::new_random();
        //compute r = k2* R1
        let mut r : GE = ephemeral_other_public_share.clone().val;
        let r = r.scalar_mul(&ephemeral_local_share.secret_share.val.get_element());


        let rx = r.get_x_coor_as_big_int().mod_floor(&temp.get_q());
        let rho = BigInt::sample_below(&temp.get_q().pow(2));
        let k2_inv = &ephemeral_local_share
            .secret_share
            .val
            .to_big_int()
            .invert(&temp.get_q())
            .unwrap();
        let partial_sig = rho * &temp.get_q() + BigInt::mod_mul(&k2_inv, message, &temp.get_q());
        let c1 = Paillier::encrypt(&ek.val, RawPlaintext::from(partial_sig));
        let v = BigInt::mod_mul(
            &k2_inv,
            &BigInt::mod_mul(
                &rx,
                &local_share.secret_share.val.to_big_int(),
                &temp.get_q(),
            ),
            &temp.get_q(),
        );
        let c2 = Paillier::mul(
            &ek.val,
            RawCiphertext::from(encrypted_secret_share.clone().val),
            RawPlaintext::from(v),
        );
        //c3:
        PartialSig {
            c3: WBigInt {
                val: Paillier::add(&ek.val, c2, c1).0.into_owned(),
                visibility: Visibility::Public,
            },
        }
    }
}
