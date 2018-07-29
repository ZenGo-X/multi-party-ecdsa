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
use super::party_one;
use cryptography_utils::arithmetic::traits::*;
use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;
use cryptography_utils::elliptic::curves::traits::*;
use cryptography_utils::BigInt;
use cryptography_utils::EC;
use cryptography_utils::PK;
use cryptography_utils::SK;
use paillier::*;
#[derive(Debug)]
pub struct KeyGenFirstMsg {
    pub d_log_proof: DLogProof,
    pub public_share: PK,
    secret_share: SK,
}

impl KeyGenFirstMsg {
    pub fn create(ec_context: &EC) -> KeyGenFirstMsg {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = SK::from_big_int(ec_context, &BigInt::sample_below(&EC::get_q()));
        pk.mul_assign(ec_context, &sk).expect("Assignment expected");
        KeyGenFirstMsg {
            d_log_proof: DLogProof::prove(&ec_context, &pk, &sk),
            public_share: pk,
            secret_share: sk,
        }
    }
}
#[derive(Debug)]
pub struct KeyGenSecondMsg {
    pub d_log_proof_result: Result<(), ProofError>,
}

impl KeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        ec_context: &EC,
        party_one_first_messsage: &party_one::KeyGenFirstMsg,
        party_one_second_messsage: &party_one::KeyGenSecondMsg,
    ) -> KeyGenSecondMsg {
        let mut flag = true;
        match party_one_first_messsage.pk_commitment
            == HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_second_messsage.public_share.to_point().x,
                &party_one_second_messsage.pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_one_first_messsage.zk_pok_commitment
            == HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_second_messsage
                    .d_log_proof
                    .pk_t_rand_commitment
                    .to_point()
                    .x,
                &party_one_second_messsage.zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        KeyGenSecondMsg {
            d_log_proof_result: DLogProof::verify(
                ec_context,
                &party_one_second_messsage.d_log_proof,
            ),
        }
    }
}

#[derive(Debug)]
pub struct PaillierPublic {
    pub ek: EncryptionKey,
    pub encrypted_secret_share: BigInt,
}

impl PaillierPublic {
    pub fn verify_range_proof(
        paillier_context: &PaillierPublic,
        challenge: &ChallengeBits,
        encrypted_pairs: &EncryptedPairs,
        proof: &Proof,
    ) -> bool {
        Paillier::verifier(
            &paillier_context.ek,
            &challenge,
            &encrypted_pairs,
            &proof,
            &EC::get_q(),
            RawCiphertext::from(&paillier_context.encrypted_secret_share),
        ).is_ok()
    }
    pub fn generate_correct_key_challenge(
        paillier_context: &PaillierPublic,
    ) -> (Challenge, VerificationAid) {
        let (challenge, verification_aid) = Paillier::challenge(&paillier_context.ek);
        (challenge, verification_aid)
    }

    pub fn verify_correct_key(
        proof: &CorrectKeyProof,
        aid: &VerificationAid,
    ) -> Result<(), CorrectKeyProofError> {
        Paillier::verify(proof, aid)
    }
}

/// 4(b)
#[derive(Debug)]
pub struct PartialSig {
    pub c3: BigInt,
}

impl PartialSig {
    pub fn compute(
        ec_context: &EC,
        ek: &EncryptionKey,
        encrypted_secret_share: &BigInt,
        local_share: &KeyGenFirstMsg,
        ephemeral_local_share: &KeyGenFirstMsg,
        ephemeral_other_share: &party_one::KeyGenFirstMsg,
        message: &BigInt,
    ) -> PartialSig {
        //compute r = k2* R1
        let mut r = ephemeral_other_share.public_share.clone();
        r.mul_assign(ec_context, &ephemeral_local_share.secret_share)
            .expect("Assignment expected");

        let rx = r.to_point().x.mod_floor(&EC::get_q());
        let rho = BigInt::sample_below(&EC::get_q().pow(2));
        let k2_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&EC::get_q())
            .unwrap();
        let partial_sig = rho * &EC::get_q() + BigInt::mod_mul(&k2_inv, message, &EC::get_q());
        let c1 = Paillier::encrypt(ek, RawPlaintext::from(partial_sig));
        let v = BigInt::mod_mul(
            &k2_inv,
            &BigInt::mod_mul(&rx, &local_share.secret_share.to_big_int(), &EC::get_q()),
            &EC::get_q(),
        );
        let c2 = Paillier::mul(
            ek,
            RawCiphertext::from(encrypted_secret_share),
            RawPlaintext::from(v),
        );
        //c3:
        PartialSig {
            c3: Paillier::add(ek, c2, c1).0.into_owned(),
        }
    }
}
