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
use super::SECURITY_BITS;
use cryptography_utils::arithmetic::traits::*;
use std::ops::Shl;

use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::BigInt;
use cryptography_utils::FE;
use cryptography_utils::GE;

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
#[derive(Debug, Serialize, Deserialize)]
pub struct PDLchallenge {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
    a: BigInt,
    b: BigInt,
    blindness: BigInt,
    q_tag: GE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLdecommit {
    pub a: BigInt,
    pub b: BigInt,
    pub blindness: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenFirstMsg {
    pub public_share: GE,
    secret_share: FE,

    pub pk_commitment: BigInt,
    pk_commitment_blind_factor: BigInt,
    pub zk_pok_commitment: BigInt,
    zk_pok_blind_factor: BigInt,
    d_log_proof: DLogProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenSecondMsg {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
}

//****************** End: Party Two structs ******************//

impl KeyGenFirstMsg {
    pub fn create() -> KeyGenFirstMsg {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = base.scalar_mul(&secret_share.get_element());

        KeyGenFirstMsg {
            d_log_proof: DLogProof::prove(&secret_share),
            public_share,
            secret_share,
        }
    }

    pub fn create_with_fixed_secret_share(secret_share: FE) -> KeyGenFirstMsg {
        let base: GE = ECPoint::generator();
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
                &party_one_public_share.x_coor(),
                &party_one_pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_one_zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_d_log_proof.pk_t_rand_commitment.x_coor(),
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

pub fn compute_pubkey(local_share: &KeyGenFirstMsg, other_share_public_share: &GE) -> GE {
    let pubkey = other_share_public_share.clone();
    pubkey.scalar_mul(&local_share.secret_share.get_element())
}

impl Party2Private {
    pub fn set_private_key(ec_key: &KeyGenFirstMsg) -> Party2Private {
        Party2Private {
            x2: ec_key.secret_share.clone(),
        }
    }
    pub fn update_private_key(party_two_private: &Party2Private, factor: &BigInt) -> Party2Private {
        let factor_fe: FE = ECScalar::from(factor);
        Party2Private {
            x2: party_two_private.x2.mul(&factor_fe.get_element()),
        }
    }
}

impl PaillierPublic {
    pub fn pdl_challenge(&self, other_share_public_share: &GE) -> PDLchallenge {
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
        let q_tag = other_share_public_share.clone() * a_fe + g * b_fe;

        PDLchallenge {
            c_tag,
            c_tag_tag,
            a,
            b,
            blindness,
            q_tag,
        }
    }

    pub fn pdl_decommit_c_tag_tag(pdl_chal: &PDLchallenge) -> PDLdecommit {
        PDLdecommit {
            a: pdl_chal.a.clone(),
            b: pdl_chal.b.clone(),
            blindness: pdl_chal.blindness.clone(),
        }
    }

    pub fn verify_pdl(
        pdl_chal: &PDLchallenge,
        blindness: &BigInt,
        q_hat: &GE,
        c_hat: &BigInt,
    ) -> Result<(), ()> {
        let c_hat_test = HashCommitment::create_commitment_with_user_defined_randomness(
            &q_hat.x_coor(),
            blindness,
        );
        if c_hat.clone() == c_hat_test
            && q_hat.get_element().clone() == pdl_chal.q_tag.get_element().clone()
        {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn verify_range_proof(
        paillier_context: &PaillierPublic,
        challenge: &ChallengeBits,
        encrypted_pairs: &EncryptedPairs,
        proof: &Proof,
    ) -> Result<(), CorrectKeyProofError> {
        let result = Paillier::verifier(
            &paillier_context.ek,
            challenge,
            encrypted_pairs,
            proof,
            &FE::q(),
            RawCiphertext::from(&paillier_context.encrypted_secret_share),
        );
        return result;
    }

    pub fn verify_ni_proof_correct_key(
        proof: NICorrectKeyProof,
        ek: &EncryptionKey,
    ) -> Result<(), CorrectKeyProofError> {
        proof.verify(&ek)
    }
}

impl EphKeyGenFirstMsg {
    pub fn create_commitments() -> EphKeyGenFirstMsg {
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

        EphKeyGenFirstMsg {
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

impl EphKeyGenSecondMsg {
    pub fn verify_and_decommit(
        first_message: &EphKeyGenFirstMsg,
        proof: &DLogProof,
    ) -> Result<EphKeyGenSecondMsg, ProofError> {
        DLogProof::verify(proof)?;
        Ok(EphKeyGenSecondMsg {
            pk_commitment_blind_factor: first_message.pk_commitment_blind_factor.clone(),
            zk_pok_blind_factor: first_message.zk_pok_blind_factor.clone(),
            public_share: first_message.public_share.clone(),
            d_log_proof: first_message.d_log_proof.clone(),
        })
    }
}

impl PartialSig {
    pub fn compute(
        ek: &EncryptionKey,
        encrypted_secret_share: &BigInt,
        local_share: &Party2Private,
        ephemeral_local_share: &EphKeyGenFirstMsg,
        ephemeral_other_public_share: &GE,
        message: &BigInt,
    ) -> PartialSig {
        let q = FE::q();
        //compute r = k2* R1
        let mut r: GE = ephemeral_other_public_share.clone();
        r = r.scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().mod_floor(&q);
        let rho = BigInt::sample_below(&q.pow(2));
        let k2_inv = &ephemeral_local_share
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
