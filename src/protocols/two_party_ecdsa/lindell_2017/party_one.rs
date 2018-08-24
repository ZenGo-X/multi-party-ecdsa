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
use cryptography_utils::FE;
use cryptography_utils::GE;

//****************** Begin: Party One structs ******************//
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenFirstMsg {
    pub public_share: GE,
    secret_share: FE,

    pub pk_commitment: BigInt,
    pk_commitment_blind_factor: BigInt,
    pub zk_pok_commitment: BigInt,
    zk_pok_blind_factor: BigInt,
    d_log_proof: DLogProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaillierKeyPair {
    pub ek: EncryptionKey,
    dk: DecryptionKey,
    pub encrypted_share: BigInt,
    randomness: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: BigInt,
    pub r: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1Private {
    x1: FE,
    paillier_priv: DecryptionKey,
}

//****************** End: Party One structs ******************//

impl KeyGenFirstMsg {
    pub fn create_commitments() -> KeyGenFirstMsg {
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
            &public_share.x_coor(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.x_coor(),
            &zk_pok_blind_factor,
        );

        KeyGenFirstMsg {
            public_share,
            secret_share,
            pk_commitment,
            pk_commitment_blind_factor,
            zk_pok_commitment,
            zk_pok_blind_factor,
            d_log_proof,
        }
    }

    pub fn create_commitments_with_fixed_secret_share(secret_share: FE) -> KeyGenFirstMsg {
        //in Lindell's protocol range proof works only for x1<q/3
        let sk_bigint = secret_share.to_big_int();
        assert!(&sk_bigint < &secret_share.q().div_floor(&BigInt::from(3)));
        let base: GE = ECPoint::generator();
        let public_share = base.scalar_mul(&secret_share.get_element());

        let d_log_proof = DLogProof::prove(&secret_share);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.x_coor(),
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.x_coor(),
            &zk_pok_blind_factor,
        );

        KeyGenFirstMsg {
            public_share,
            secret_share,
            pk_commitment,
            pk_commitment_blind_factor,
            zk_pok_commitment,
            zk_pok_blind_factor,
            d_log_proof,
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
            pk_commitment_blind_factor: first_message.pk_commitment_blind_factor.clone(),
            zk_pok_blind_factor: first_message.zk_pok_blind_factor.clone(),
            public_share: first_message.public_share.clone(),
            d_log_proof: first_message.d_log_proof.clone(),
        })
    }
}

pub fn compute_pubkey(local_share: &KeyGenFirstMsg, other_share_public_share: &GE) -> GE {
    let pubkey = other_share_public_share.clone();
    pubkey.scalar_mul(&local_share.secret_share.get_element())
}

impl Party1Private {
    pub fn set_private_key(
        ec_key: &KeyGenFirstMsg,
        paillier_key: &PaillierKeyPair,
    ) -> Party1Private {
        Party1Private {
            x1: ec_key.secret_share.clone(),
            paillier_priv: paillier_key.dk.clone(),
        }
    }
    pub fn update_private_key(party_one_private: &Party1Private, factor: &BigInt) -> Party1Private {
        let factor_fe: FE = ECScalar::from(factor);
        Party1Private {
            x1: party_one_private.x1.mul(&factor_fe.get_element()),
            paillier_priv: party_one_private.paillier_priv.clone(),
        }
    }
}

impl PaillierKeyPair {
    pub fn generate_keypair_and_encrypted_share(keygen: &KeyGenFirstMsg) -> PaillierKeyPair {
        let (ek, dk) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek);

        let encrypted_share = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(keygen.secret_share.to_big_int()),
            &randomness,
        ).0
        .into_owned();

        PaillierKeyPair {
            ek,
            dk,
            encrypted_share,
            randomness: randomness.0,
        }
    }

    pub fn generate_range_proof(
        paillier_context: &PaillierKeyPair,
        keygen: &KeyGenFirstMsg,
    ) -> (EncryptedPairs, ChallengeBits, Proof) {
        let temp: FE = ECScalar::new_random();
        let (encrypted_pairs, challenge, proof) = Paillier::prover(
            &paillier_context.ek,
            &temp.q(),
            &keygen.secret_share.to_big_int(),
            &paillier_context.randomness,
        );

        (encrypted_pairs, challenge, proof)
    }

    pub fn generate_proof_correct_key(
        paillier_context: &PaillierKeyPair,
        challenge: &Challenge,
    ) -> Result<CorrectKeyProof, CorrectKeyProofError> {
        Ok(Paillier::prove(&paillier_context.dk, challenge).unwrap())
    }
}

impl Signature {
    pub fn compute(
        party_one_private: &Party1Private,
        partial_sig_c3: &BigInt,
        ephemeral_local_share: &KeyGenFirstMsg,
        ephemeral_other_public_share: &GE,
    ) -> Signature {
        //compute r = k2* R1
        let temp: FE = ECScalar::new_random();
        let mut r = ephemeral_other_public_share.clone();
        r = r.scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().mod_floor(&temp.q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&temp.q())
            .unwrap();
        let s_tag = Paillier::decrypt(
            &party_one_private.paillier_priv,
            &RawCiphertext::from(partial_sig_c3),
        );
        let s_tag_tag = BigInt::mod_mul(&k1_inv, &s_tag.0, &temp.q());
        let s = cmp::min(s_tag_tag.clone(), &temp.q().clone() - s_tag_tag.clone());

        Signature { s, r: rx }
    }
}

pub fn verify(signature: &Signature, pubkey: &GE, message: &BigInt) -> Result<(), ProofError> {
    let temp: FE = ECScalar::new_random();
    let b = signature.s.invert(&temp.q()).unwrap().mod_floor(&temp.q());
    let a = message.mod_floor(&temp.q());
    let u1 = BigInt::mod_mul(&a, &b, &temp.q());
    let u2 = BigInt::mod_mul(&signature.r, &b, &temp.q());
    // can be faster using shamir trick
    let mut point1: GE = ECPoint::generator();
    let u1_fe: FE = ECScalar::from(&u1);
    let u2_fe: FE = ECScalar::from(&u2);

    point1 = point1.scalar_mul(&u1_fe.get_element());

    let mut point2 = pubkey.clone();
    point2 = point2.scalar_mul(&u2_fe.get_element());

    if signature.r == point1.add_point(&point2.get_element()).x_coor() {
        Ok(())
    } else {
        Err(ProofError)
    }
}
