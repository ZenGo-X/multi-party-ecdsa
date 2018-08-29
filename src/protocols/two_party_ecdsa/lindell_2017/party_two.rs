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
use cryptography_utils::FE;
use cryptography_utils::GE;

use super::party_one;
use paillier::*;
//****************** Begin: Party Two structs ******************//

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub d_log_proof: DLogProof,
    pub public_share: GE,
    secret_share: FE,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2Private {
    x2: FE,
}

//****************** End: Party Two structs ******************//

impl KeyGenFirstMsg {
    pub fn create() -> KeyGenFirstMsg {
        let base: GE = ECPoint::new();
        let secret_share: FE = ECScalar::new_random();
        let public_share = base.scalar_mul(&secret_share.get_element());

        KeyGenFirstMsg {
            d_log_proof: DLogProof::prove(&secret_share),
            public_share,
            secret_share,
        }
    }

    pub fn create_with_fixed_secret_share(secret_share: FE) -> KeyGenFirstMsg {
        let base: GE = ECPoint::new();
        let public_share = base.scalar_mul(&secret_share.get_element());
        KeyGenFirstMsg {
            d_log_proof: DLogProof::prove(&secret_share),
            public_share,
            secret_share,
        }
    }
}

impl KeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        party_one_pk_commitment: &BigInt,
        party_one_zk_pok_commitment: &BigInt,
        party_one_zk_pok_blind_factor: &BigInt,
        party_one_public_share: &GE,
        party_one_pk_commitment_blind_factor: &BigInt,
        party_one_d_log_proof: &DLogProof,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        let mut flag = true;
        match party_one_pk_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_public_share.get_x_coor_as_big_int(),
                &party_one_pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_one_zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_d_log_proof
                    .pk_t_rand_commitment
                    .get_x_coor_as_big_int(),
                &party_one_zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        DLogProof::verify(&party_one_d_log_proof)?;
        Ok(KeyGenSecondMsg {})
    }
}

pub fn compute_pubkey(local_share: &KeyGenFirstMsg, other_share: &party_one::KeyGenFirstMsg) -> GE {
    let pubkey = other_share.public_share.clone();
    pubkey.scalar_mul(&local_share.secret_share.get_element())
}
impl Party2Private {
    pub fn set_private_key(ec_key: &KeyGenFirstMsg) -> Party2Private {
        Party2Private {
            x2: ec_key.secret_share.clone(),
        }
    }
    pub fn update_private_key(party_two_private: &Party2Private, factor: &BigInt) -> Party2Private {
        let factor_fe: FE = ECScalar::from_big_int(factor);
        Party2Private {
            x2: party_two_private.x2.mul(&factor_fe.get_element()),
        }
    }
}

impl PaillierPublic {
    pub fn verify_range_proof(
        paillier_context: &PaillierPublic,
        challenge: &ChallengeBits,
        encrypted_pairs: &EncryptedPairs,
        proof: &Proof,
    ) -> Result<(), CorrectKeyProofError> {
        let temp: FE = ECScalar::new_random();
        let result = Paillier::verifier(
            &paillier_context.ek,
            challenge,
            encrypted_pairs,
            proof,
            &temp.get_q(),
            RawCiphertext::from(&paillier_context.encrypted_secret_share),
        );
        return result;
    }
    pub fn generate_correct_key_challenge(
        paillier_context: &PaillierPublic,
    ) -> (Challenge, VerificationAid) {
        Paillier::challenge(&paillier_context.ek)
    }

    pub fn verify_correct_key(
        proof: &CorrectKeyProof,
        aid: &VerificationAid,
    ) -> Result<(), CorrectKeyProofError> {
        Paillier::verify(&proof, &aid)
    }
}

impl PartialSig {
    pub fn compute(
        ek: &EncryptionKey,
        encrypted_secret_share: &BigInt,
        local_share: &Party2Private,
        ephemeral_local_share: &KeyGenFirstMsg,
        ephemeral_other_public_share: &GE,
        message: &BigInt,
    ) -> PartialSig {
        let temp: FE = ECScalar::new_random();
        //compute r = k2* R1
        let mut r: GE = ephemeral_other_public_share.clone();
        r = r.scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.get_x_coor_as_big_int().mod_floor(&temp.get_q());
        let rho = BigInt::sample_below(&temp.get_q().pow(2));
        let k2_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&temp.get_q())
            .unwrap();
        let partial_sig = rho * &temp.get_q() + BigInt::mod_mul(&k2_inv, message, &temp.get_q());
        let c1 = Paillier::encrypt(ek, RawPlaintext::from(partial_sig));
        let v = BigInt::mod_mul(
            &k2_inv,
            &BigInt::mod_mul(&rx, &local_share.x2.to_big_int(), &temp.get_q()),
            &temp.get_q(),
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
