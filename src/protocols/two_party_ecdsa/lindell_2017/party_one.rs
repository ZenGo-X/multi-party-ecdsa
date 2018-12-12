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
use paillier::Paillier;
use paillier::{Decrypt, EncryptWithChosenRandomness, KeyGeneration};
use paillier::{DecryptionKey, EncryptionKey, Randomness, RawCiphertext, RawPlaintext};
use std::cmp;
use std::ops::Shl;
use zk_paillier::zkproofs::{
    EqualMessageProof, NICorrectKeyProof, NISigmaProof as SigmaTrait, RangeProofNi,
    Statement as SameMessageStatement, Witness as SameMessageWitness,
};

use super::SECURITY_BITS;
use curv::arithmetic::traits::*;

use curv::elliptic::curves::traits::*;

use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives::proofs::ProofError;
use protocols::two_party_ecdsa::lindell_2017::party_two::EphKeyGenFirstMsg as Party2EphKeyGenFirstMessage;
use protocols::two_party_ecdsa::lindell_2017::party_two::EphKeyGenSecondMsg as Party2EphKeyGenSecondMessage;

use curv::BigInt;
use curv::FE;
use curv::GE;

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
pub struct Signature {
    pub s: BigInt,
    pub r: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party1Private {
    x1: FE,
    paillier_priv: DecryptionKey,
    c_key_randomness: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDL {
    alpha: BigInt,
    q_hat: GE,
    blindness: BigInt,
    pub c_hat: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLdecommit {
    pub q_hat: GE,
    pub blindness: BigInt,
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
        secret_share: FE,
    ) -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        //in Lindell's protocol range proof works only for x1<q/3
        let sk_bigint = secret_share.to_big_int();
        let q_third = FE::q();
        assert!(&sk_bigint < &q_third.div_floor(&BigInt::from(3)));
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
        proof: &DLogProof,
    ) -> Result<KeyGenSecondMsg, ProofError> {
        DLogProof::verify(proof)?;
        Ok(KeyGenSecondMsg { comm_witness })
    }
}

pub fn compute_pubkey(local_share: &EcKeyPair, other_share_public_share: &GE) -> GE {
    other_share_public_share * &local_share.secret_share
}

impl Party1Private {
    pub fn set_private_key(ec_key: &EcKeyPair, paillier_key: &PaillierKeyPair) -> Party1Private {
        Party1Private {
            x1: ec_key.secret_share.clone(),
            paillier_priv: paillier_key.dk.clone(),
            c_key_randomness: paillier_key.randomness.clone(),
        }
    }
    pub fn update_private_key(party_one_private: &Party1Private, factor: &BigInt) -> Party1Private {
        let new_randomness_bn =
            BigInt::mod_pow(&party_one_private.c_key_randomness, factor, &party_one_private.paillier_priv.n);
        let factor_fe: FE = ECScalar::from(factor);
        Party1Private {
            x1: party_one_private.x1.mul(&factor_fe.get_element()),
            paillier_priv: party_one_private.paillier_priv.clone(),
            c_key_randomness: new_randomness_bn,
        }
    }

    pub fn paillier_refresh(
        &self,
        c_key_old: &BigInt,
        ek_old: &EncryptionKey,
    ) -> (
        EncryptionKey,
        BigInt,
        Party1Private,
        NICorrectKeyProof,
        EqualMessageProof,
    ) {
        let (ek_new, dk_new) = Paillier::keypair().keys();
        let randomness = Randomness::sample(&ek_new);
        let c_key_new = Paillier::encrypt_with_chosen_randomness(
            &ek_new,
            RawPlaintext::from(self.x1.to_big_int().clone()),
            &randomness,
        )
        .0
        .into_owned();
        let correct_key_proof_new = NICorrectKeyProof::proof(&dk_new);
        let witness = SameMessageWitness {
            x: RawPlaintext::from(self.x1.to_big_int().clone()),
            r1: Randomness::from(self.c_key_randomness.clone()),
            r2: randomness,
        };

        let statement = SameMessageStatement {
            c1: RawCiphertext::from(c_key_old.clone()),
            ek1: ek_old.clone(),
            c2: RawCiphertext::from(c_key_new.clone()),
            ek2: ek_new.clone(),
        };

        let equal_message_proof = EqualMessageProof::prove(&witness, &statement);
        println!("verify : {:?}", equal_message_proof.verify(&statement));

        let new_private = Party1Private {
            x1: self.x1.clone(),
            paillier_priv: dk_new,
            c_key_randomness: witness.r2.0.clone(),
        };
        (
            ek_new,
            c_key_new,
            new_private,
            correct_key_proof_new,
            equal_message_proof,
        )
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

    pub fn generate_range_proof(
        paillier_context: &PaillierKeyPair,
        keygen: &EcKeyPair,
    ) -> RangeProofNi {
        let range_proof = RangeProofNi::prove(
            &paillier_context.ek,
            &FE::q(),
            &paillier_context.encrypted_share.clone(),
            &keygen.secret_share.to_big_int(),
            &paillier_context.randomness,
        );
        range_proof
    }

    pub fn generate_ni_proof_correct_key(paillier_context: &PaillierKeyPair) -> NICorrectKeyProof {
        NICorrectKeyProof::proof(&paillier_context.dk)
    }

    pub fn pdl_first_stage(&self, c_tag: &BigInt) -> PDL {
        let alpha = Paillier::decrypt(&self.dk, &RawCiphertext::from(c_tag.clone()));
        let alpha_fe: FE = ECScalar::from(&alpha.0);
        let g: GE = ECPoint::generator();
        let q_hat = g * &alpha_fe;
        let blindness = BigInt::sample_below(&FE::q());
        let c_hat = HashCommitment::create_commitment_with_user_defined_randomness(
            &q_hat.x_coor(),
            &blindness,
        );

        PDL {
            alpha: alpha.0.into_owned(),
            q_hat: q_hat,
            blindness,
            c_hat,
        }
    }

    pub fn pdl_second_stage(
        pdl: &PDL,
        c_tag_tag: &BigInt,
        ec_key_pair: EcKeyPair,
        a: &BigInt,
        b: &BigInt,
        blindness: &BigInt,
    ) -> Result<(PDLdecommit), ()> {
        let ab_concat = a.clone() + b.clone().shl(a.bit_length());
        let c_tag_tag_test =
            HashCommitment::create_commitment_with_user_defined_randomness(&ab_concat, &blindness);
        let ax1 = a.clone() * ec_key_pair.secret_share.to_big_int();
        let alpha_test = ax1 + b.clone();
        let pdl_decom = PDLdecommit {
            q_hat: pdl.q_hat.clone(),
            blindness: pdl.blindness.clone(),
        };
        if alpha_test == pdl.alpha && c_tag_tag.clone() == c_tag_tag_test {
            Ok(pdl_decom)
        } else {
            Err(())
        }
    }
}

impl EphKeyGenFirstMsg {
    pub fn create() -> (EphKeyGenFirstMsg, EphEcKeyPair) {
        let base: GE = ECPoint::generator();
        let secret_share: FE = ECScalar::new_random();
        let public_share = &base * &secret_share;
        let h: GE = GE::base_point2();
        let w = ECDDHWitness {
            x: secret_share.clone(),
        };
        let c = &h * &secret_share;
        let delta = ECDDHStatement {
            g1: base.clone(),
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
        match party_two_pk_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &party_two_public_share.x_coor(),
                &party_two_pk_commitment_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        match party_two_zk_pok_commitment
            == &HashCommitment::create_commitment_with_user_defined_randomness(
                &HSha256::create_hash_from_ge(&[
                    &party_two_d_log_proof.a1,
                    &party_two_d_log_proof.a2,
                ])
                .to_big_int(),
                &party_two_zk_pok_blind_factor,
            ) {
            false => flag = false,
            true => flag = flag,
        };
        assert!(flag);
        let delta = ECDDHStatement {
            g1: GE::generator(),
            h1: party_two_public_share.clone(),
            g2: GE::base_point2(),
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
        ephemeral_other_public_share: &GE,
    ) -> Signature {
        //compute r = k2* R1
        let mut r = ephemeral_other_public_share.clone();
        r = r.scalar_mul(&ephemeral_local_share.secret_share.get_element());

        let rx = r.x_coor().mod_floor(&FE::q());
        let k1_inv = &ephemeral_local_share
            .secret_share
            .to_big_int()
            .invert(&FE::q())
            .unwrap();
        let s_tag = Paillier::decrypt(
            &party_one_private.paillier_priv,
            &RawCiphertext::from(partial_sig_c3),
        );
        let s_tag_tag = BigInt::mod_mul(&k1_inv, &s_tag.0, &FE::q());
        let s = cmp::min(s_tag_tag.clone(), FE::q().clone() - s_tag_tag.clone());

        Signature { s, r: rx }
    }
}

pub fn verify(signature: &Signature, pubkey: &GE, message: &BigInt) -> Result<(), ProofError> {
    let q = FE::q();
    let b = signature.s.invert(&q).unwrap().mod_floor(&q);
    let a = message.mod_floor(&q);
    let u1 = BigInt::mod_mul(&a, &b, &q);
    let u2 = BigInt::mod_mul(&signature.r, &b, &q);
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
