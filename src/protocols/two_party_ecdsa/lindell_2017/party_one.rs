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

use cryptography_utils::BigInt;

use cryptography_utils::RawPoint;
use cryptography_utils::EC;
use cryptography_utils::PK;
use cryptography_utils::SK;

const SECURITY_BITS: usize = 256;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::cryptographic_primitives::proofs::ProofError;

use super::party_two;
use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use paillier::*;
use std::cmp;

//****************** Begin: Party One structs ******************//
#[derive(Debug)]
pub struct KeyGenFirstMsg {
    public_share: PK,
    secret_share: SK,
    pub pk_commitment: BigInt,
    pk_commitment_blind_factor: BigInt,

    pub zk_pok_commitment: BigInt,
    zk_pok_blind_factor: BigInt,

    d_log_proof: DLogProof,
}

#[derive(Debug)]
pub struct KeyGenSecondMsg {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: PK,
    pub d_log_proof: DLogProof,
}

#[derive(Debug)]
pub struct PaillierKeyPair {
    pub ek: EncryptionKey,
    dk: DecryptionKey,
    pub encrypted_share: BigInt,
    randomness: BigInt,
}

#[derive(Debug)]
pub struct Signature {
    pub s: BigInt,
    pub r: BigInt,
}

//****************** End: Party One structs ******************//

//****************** Begin: Party One RAW structs ******************//

#[derive(Serialize, Deserialize)]
pub struct RawKeyGenFirstMsg {
    pub public_share: RawPoint,
    secret_share: String,
    pub pk_commitment: String,
    pk_commitment_blind_factor: String,

    pub zk_pok_commitment: String,
    zk_pok_blind_factor: String,

    d_log_proof: RawDLogProof,
}

#[derive(Serialize, Deserialize)]
pub struct RawKeyGenSecondMsg {
    pub pk_commitment_blind_factor: String,
    pub zk_pok_blind_factor: String,
    pub public_share: RawPoint,
    pub d_log_proof: RawDLogProof,
}

// TODO: add remaining struct

impl From<KeyGenFirstMsg> for RawKeyGenFirstMsg {
    fn from(po_keygen_first_message: KeyGenFirstMsg) -> Self {
        RawKeyGenFirstMsg {
            public_share: RawPoint::from(po_keygen_first_message.public_share.to_point()),
            secret_share: po_keygen_first_message.secret_share.to_big_int().to_hex(),
            pk_commitment: po_keygen_first_message.pk_commitment.to_hex(),
            pk_commitment_blind_factor: po_keygen_first_message.pk_commitment_blind_factor.to_hex(),
            zk_pok_commitment: po_keygen_first_message.zk_pok_commitment.to_hex(),
            zk_pok_blind_factor: po_keygen_first_message.zk_pok_blind_factor.to_hex(),
            d_log_proof: RawDLogProof::from(po_keygen_first_message.d_log_proof),
        }
    }
}

impl From<KeyGenSecondMsg> for RawKeyGenSecondMsg {
    fn from(po_key_gen_second_message: KeyGenSecondMsg) -> Self {
        RawKeyGenSecondMsg {
            pk_commitment_blind_factor: po_key_gen_second_message
                .pk_commitment_blind_factor
                .to_hex(),
            zk_pok_blind_factor: po_key_gen_second_message.zk_pok_blind_factor.to_hex(),
            public_share: RawPoint::from(po_key_gen_second_message.public_share.to_point()),
            d_log_proof: RawDLogProof::from(po_key_gen_second_message.d_log_proof),
        }
    }
}

//****************** End: Party One RAW structs ******************//

impl KeyGenFirstMsg {
    pub fn create_commitments(ec_context: &EC) -> KeyGenFirstMsg {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());

        //in Lindell's protocol range proof works only for x1<q/3
        let sk = SK::from_big_int(
            ec_context,
            &BigInt::sample_below(&EC::get_q().div_floor(&BigInt::from(3))),
        );
        pk.mul_assign(ec_context, &sk).expect("Assignment expected");

        let d_log_proof = DLogProof::prove(&ec_context, &pk, &sk);

        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &pk.to_point().x,
            &pk_commitment_blind_factor,
        );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof.pk_t_rand_commitment.to_point().x,
            &zk_pok_blind_factor,
        );

        KeyGenFirstMsg {
            public_share: pk,
            secret_share: sk,
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
        ec_context: &EC,
        first_message: &KeyGenFirstMsg,
        proof: &DLogProof,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(ec_context, proof)?;
        Ok(KeyGenSecondMsg {
            pk_commitment_blind_factor: first_message.pk_commitment_blind_factor.clone(),
            zk_pok_blind_factor: first_message.zk_pok_blind_factor.clone(),
            public_share: first_message.public_share.clone(),
            d_log_proof: first_message.d_log_proof.clone(),
        })
    }
}

pub fn compute_pubkey(
    ec_context: &EC,
    local_share: &KeyGenFirstMsg,
    other_share: &party_two::KeyGenFirstMsg,
) -> PK {
    let mut pubkey = other_share.public_share.clone();
    pubkey
        .mul_assign(ec_context, &local_share.secret_share)
        .expect("Failed to multiply and assign");

    return pubkey;
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
        let (encrypted_pairs, challenge, proof) = Paillier::prover(
            &paillier_context.ek,
            &EC::get_q(),
            &keygen.secret_share.to_big_int(),
            &paillier_context.randomness,
        );

        (encrypted_pairs, challenge, proof)
    }

    pub fn generate_proof_correct_key(
        paillier_context: &PaillierKeyPair,
        challenge: &Challenge,
    ) -> Result<CorrectKeyProof, CorrectKeyProofError> {
        Paillier::prove(&paillier_context.dk, challenge)
    }
}

impl Signature {
    pub fn compute(
        ec_context: &EC,
        keypair: &PaillierKeyPair,
        partial_sig: &party_two::PartialSig,
        ephemeral_local_share: &KeyGenFirstMsg,
        ephemeral_other_share: &party_two::KeyGenFirstMsg,
    ) -> Signature {
        //compute r = k2* R1
        let mut r = ephemeral_other_share.public_share.clone();
        r.mul_assign(ec_context, &ephemeral_local_share.secret_share)
            .expect("Failed to multiply and assign");

        let rx = r.to_point().x.mod_floor(&EC::get_q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&EC::get_q())
            .unwrap();
        let s_tag = Paillier::decrypt(&keypair.dk, &RawCiphertext::from(&partial_sig.c3));
        let s_tag_tag = BigInt::mod_mul(&k1_inv, &s_tag.0, &EC::get_q());
        let s = cmp::min(s_tag_tag.clone(), &EC::get_q().clone() - s_tag_tag.clone());

        Signature { s, r: rx }
    }
}

pub fn verify(
    ec_context: &EC,
    signature: &Signature,
    pubkey: &PK,
    message: &BigInt,
) -> Result<(), ProofError> {
    let b = signature
        .s
        .invert(&EC::get_q())
        .unwrap()
        .mod_floor(&EC::get_q());
    let a = message.mod_floor(&EC::get_q());
    let u1 = BigInt::mod_mul(&a, &b, &EC::get_q());
    let u2 = BigInt::mod_mul(&signature.r, &b, &EC::get_q());
    // can be faster using shamir trick
    let mut point1 = PK::to_key(ec_context, &EC::get_base_point());

    point1
        .mul_assign(ec_context, &SK::from_big_int(ec_context, &u1))
        .expect("Failed to multiply and assign");

    let mut point2 = *pubkey;
    point2
        .mul_assign(ec_context, &SK::from_big_int(ec_context, &u2))
        .expect("Failed to multiply and assign");

    if signature.r == point1.combine(ec_context, &point2).unwrap().to_point().x {
        Ok(())
    } else {
        Err(ProofError)
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
    fn test_party_one_keygen_serialization_first_msg() {
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

        let party_one_first_message = KeyGenFirstMsg {
            public_share: PK::from_slice(&s, &valid_key).unwrap(),
            secret_share: SK::from_big_int(&s, &BigInt::from(1)),
            pk_commitment: BigInt::from(2),
            pk_commitment_blind_factor: BigInt::from(3),
            zk_pok_commitment: BigInt::from(4),
            zk_pok_blind_factor: BigInt::from(5),
            d_log_proof: d_log_proof,
        };

        let party_one_keygen_raw_first_message = RawKeyGenFirstMsg::from(party_one_first_message);

        let res = serde_json::to_string(&party_one_keygen_raw_first_message)
            .expect("Failed in serialization");

        assert_eq!(
            res,
            "{\"public_share\":\
             {\"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"secret_share\":\"1\",\
             \"pk_commitment\":\"2\",\
             \"pk_commitment_blind_factor\":\"3\",\
             \"zk_pok_commitment\":\"4\",\
             \"zk_pok_blind_factor\":\"5\",\
             \"d_log_proof\":\
             {\"pk\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"pk_t_rand_commitment\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"challenge_response\":\"b\"}}"
        );
    }

    #[test]
    fn test_party_one_keygen_serialization_second_msg() {
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

        let party_one_second_message = KeyGenSecondMsg {
            public_share: PK::from_slice(&s, &valid_key).unwrap(),
            pk_commitment_blind_factor: BigInt::from(3),
            zk_pok_blind_factor: BigInt::from(5),
            d_log_proof: d_log_proof,
        };

        let party_one_keygen_raw_second_message =
            RawKeyGenSecondMsg::from(party_one_second_message);

        let res = serde_json::to_string(&party_one_keygen_raw_second_message)
            .expect("Failed in serialization");

        assert_eq!(
            res,
            "{\"pk_commitment_blind_factor\":\"3\",\
             \"zk_pok_blind_factor\":\"5\",\
             \"public_share\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"d_log_proof\":{\
             \"pk\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"pk_t_rand_commitment\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"challenge_response\":\"b\"}}"
        );
    }
}
