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
use cryptography_utils::RawPoint;
use cryptography_utils::EC;
use cryptography_utils::PK;
use cryptography_utils::SK;

use paillier::*;

use super::party_one;

//****************** Begin: Party Two structs ******************//

#[derive(Debug)]
pub struct KeyGenFirstMsg {
    pub d_log_proof: DLogProof,
    pub public_share: PK,
    secret_share: SK,
}

#[derive(Debug)]
pub struct KeyGenSecondMsg {}

#[derive(Debug)]
pub struct PaillierPublic {
    pub ek: EncryptionKey,
    pub encrypted_secret_share: BigInt,
}

#[derive(Debug)]
pub struct PartialSig {
    pub c3: BigInt,
}

//****************** End: Party Two structs ******************//

//****************** Begin: Party Two RAW structs ******************//

#[derive(Serialize, Deserialize)]
pub struct RawKeyGenFirstMsg {
    pub d_log_proof: RawDLogProof,
    pub public_share: RawPoint,
    secret_share: String,
}

// TODO: add remaining struct

impl From<KeyGenFirstMsg> for RawKeyGenFirstMsg {
    fn from(pt_key_gen_first_message: KeyGenFirstMsg) -> Self {
        RawKeyGenFirstMsg {
            d_log_proof: RawDLogProof::from(pt_key_gen_first_message.d_log_proof),
            public_share: RawPoint::from(pt_key_gen_first_message.public_share.to_point()),
            secret_share: pt_key_gen_first_message.secret_share.to_big_int().to_hex(),
        }
    }
}
//****************** End: Party Two RAW structs ******************//

impl KeyGenFirstMsg {
    pub fn create(ec_context: &EC) -> KeyGenFirstMsg {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = SK::from_big_int(ec_context, &BigInt::sample_below(&EC::get_q()));
        pk.mul_assign(ec_context, &sk)
            .expect("Failed to multiply and assign");
        KeyGenFirstMsg {
            d_log_proof: DLogProof::prove(&ec_context, &pk, &sk),
            public_share: pk,
            secret_share: sk,
        }
    }
}

impl KeyGenSecondMsg {
    pub fn verify_commitments_and_dlog_proof(
        ec_context: &EC,
        party_one_first_message: &party_one::KeyGenFirstMsg,
        party_one_second_message: &party_one::KeyGenSecondMsg,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        let mut flag = true;
        match party_one_first_message.pk_commitment
            == HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_second_message.public_share.to_point().x,
                &party_one_second_message.pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_one_first_message.zk_pok_commitment
            == HashCommitment::create_commitment_with_user_defined_randomness(
                &party_one_second_message
                    .d_log_proof
                    .pk_t_rand_commitment
                    .to_point()
                    .x,
                &party_one_second_message.zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        DLogProof::verify(ec_context, &party_one_second_message.d_log_proof)?;
        Ok(KeyGenSecondMsg {})
    }
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

impl PartialSig {
    pub fn compute(
        ec_context: &EC,
        ek: &EncryptionKey,
        encrypted_secret_share: &BigInt,
        local_share: &KeyGenFirstMsg,
        ephemeral_local_share: &KeyGenFirstMsg,
        ephemeral_other_share: &party_one::KeyGenSecondMsg,
        message: &BigInt,
    ) -> PartialSig {
        //compute r = k2* R1
        let mut r = ephemeral_other_share.public_share.clone();
        r.mul_assign(ec_context, &ephemeral_local_share.secret_share)
            .expect("Failed to multiply and assign");

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

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography_utils::EC;
    use cryptography_utils::PK;
    use cryptography_utils::SK;
    use serde_json;

    #[test]
    fn test_party_two_keygen_serialization_first_message() {
        let valid_key: [u8; PK::KEY_SIZE] = [
            4, // header
            // X
            54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220,
            40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, // Y
            57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193,
            86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188,
        ];

        let s = EC::new();

        let d_log_proof = DLogProof {
            pk: PK::from_slice(&s, &valid_key).unwrap(),
            pk_t_rand_commitment: PK::from_slice(&s, &valid_key).unwrap(),
            challenge_response: BigInt::from(11),
        };

        let party_two_keygen_first_msg = KeyGenFirstMsg {
            d_log_proof: d_log_proof,
            public_share: PK::from_slice(&s, &valid_key).unwrap(),
            secret_share: SK::from_big_int(&s, &BigInt::from(1)),
        };

        let party_two_keygen_raw_first_msg = RawKeyGenFirstMsg::from(party_two_keygen_first_msg);

        let res = serde_json::to_string(&party_two_keygen_raw_first_msg)
            .expect("Failed in serialization");

        assert_eq!(
            res,
            "{\"d_log_proof\":{\
             \"pk\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"pk_t_rand_commitment\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"challenge_response\":\"b\"},\
             \"public_share\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"secret_share\":\"1\"}"
        );
    }
}
