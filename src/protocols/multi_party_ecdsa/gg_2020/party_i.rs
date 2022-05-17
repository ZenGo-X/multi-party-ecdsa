#![allow(non_snake_case)]

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

use std::fmt::Debug;

use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;

use crate::Error::{self, InvalidSig, Phase5BadSum, Phase6Error};
use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};

use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NiCorrectKeyProof;
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

use crate::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use crate::utilities::zk_pdl_with_slack::{PDLwSlackProof, PDLwSlackStatement, PDLwSlackWitness};
use curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;

use std::convert::TryInto;

const SECURITY: usize = 256;
const PAILLIER_MIN_BIT_LENGTH: usize = 2047;
const PAILLIER_MAX_BIT_LENGTH: usize = 2048;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Keys<E: Curve = Secp256k1> {
    pub u_i: Scalar<E>,
    pub y_i: Point<E>,
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub party_index: usize,
    pub N_tilde: BigInt,
    pub h1: BigInt,
    pub h2: BigInt,
    pub xhi: BigInt,
    pub xhi_inv: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyPrivate {
    u_i: Scalar<Secp256k1>,
    x_i: Scalar<Secp256k1>,
    dk: DecryptionKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenBroadcastMessage1 {
    pub e: EncryptionKey,
    pub dlog_statement: DLogStatement,
    pub com: BigInt,
    pub correct_key_proof: NiCorrectKeyProof,
    pub composite_dlog_proof_base_h1: CompositeDLogProof,
    pub composite_dlog_proof_base_h2: CompositeDLogProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage1 {
    pub blind_factor: BigInt,
    pub y_i: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: Point<Secp256k1>,
    pub x_i: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignKeys {
    pub w_i: Scalar<Secp256k1>,
    pub g_w_i: Point<Secp256k1>,
    pub k_i: Scalar<Secp256k1>,
    pub gamma_i: Scalar<Secp256k1>,
    pub g_gamma_i: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignBroadcastPhase1 {
    pub com: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignDecommitPhase1 {
    pub blind_factor: BigInt,
    pub g_gamma_i: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSignature {
    pub r: Scalar<Secp256k1>,
    pub R: Point<Secp256k1>,
    pub s_i: Scalar<Secp256k1>,
    pub m: BigInt,
    pub y: Point<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub r: Scalar<Secp256k1>,
    pub s: Scalar<Secp256k1>,
    pub recid: u8,
}

pub fn generate_h1_h2_N_tilde() -> (BigInt, BigInt, BigInt, BigInt, BigInt) {
    // note, should be safe primes:
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();;
    let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
    let one = BigInt::one();
    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    let h1 = BigInt::sample_below(&ek_tilde.n);
    let (mut xhi, mut xhi_inv) = loop {
        let xhi_ = BigInt::sample_below(&phi);
        match BigInt::mod_inv(&xhi_, &phi) {
            Some(inv) => break (xhi_, inv),
            None => continue,
        }
    };
    let h2 = BigInt::mod_pow(&h1, &xhi, &ek_tilde.n);
    xhi = BigInt::sub(&phi, &xhi);
    xhi_inv = BigInt::sub(&phi, &xhi_inv);

    (ek_tilde.n, h1, h2, xhi, xhi_inv)
}

impl Keys {
    pub fn create(index: usize) -> Self {
        let u = Scalar::<Secp256k1>::random();
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();
        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn create_safe_prime(index: usize) -> Self {
        let u = Scalar::<Secp256k1>::random();
        let y = Point::generator() * &u;

        let (ek, dk) = Paillier::keypair_safe_primes().keys();
        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }
    pub fn create_from(u: Scalar<Secp256k1>, index: usize) -> Self {
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();
        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }

    pub fn phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2(
        &self,
    ) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        let blind_factor = BigInt::sample(SECURITY);
        let correct_key_proof = NiCorrectKeyProof::proof(&self.dk, None);

        let dlog_statement_base_h1 = DLogStatement {
            N: self.N_tilde.clone(),
            g: self.h1.clone(),
            ni: self.h2.clone(),
        };
        let dlog_statement_base_h2 = DLogStatement {
            N: self.N_tilde.clone(),
            g: self.h2.clone(),
            ni: self.h1.clone(),
        };

        let composite_dlog_proof_base_h1 =
            CompositeDLogProof::prove(&dlog_statement_base_h1, &self.xhi);
        let composite_dlog_proof_base_h2 =
            CompositeDLogProof::prove(&dlog_statement_base_h2, &self.xhi_inv);

        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(self.y_i.to_bytes(true).as_ref()),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 {
            e: self.ek.clone(),
            dlog_statement: dlog_statement_base_h1,
            com,
            correct_key_proof,
            composite_dlog_proof_base_h1,
            composite_dlog_proof_base_h2,
        };
        let decom1 = KeyGenDecommitMessage1 {
            blind_factor,
            y_i: self.y_i.clone(),
        };
        (bcm1, decom1)
    }

    pub fn phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
        &self,
        params: &Parameters,
        decom_vec: &[KeyGenDecommitMessage1],
        bc1_vec: &[KeyGenBroadcastMessage1],
    ) -> Result<(VerifiableSS<Secp256k1>, Vec<Scalar<Secp256k1>>, usize), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        // test length:
        assert_eq!(decom_vec.len(), usize::from(params.share_count));
        assert_eq!(bc1_vec.len(), usize::from(params.share_count));
        // test paillier correct key, h1,h2 correct generation and test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                let dlog_statement_base_h2 = DLogStatement {
                    N: bc1_vec[i].dlog_statement.N.clone(),
                    g: bc1_vec[i].dlog_statement.ni.clone(),
                    ni: bc1_vec[i].dlog_statement.g.clone(),
                };
                let test_res =
                    HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                        &BigInt::from_bytes(&decom_vec[i].y_i.to_bytes(true)),
                        &decom_vec[i].blind_factor,
                    ) == bc1_vec[i].com
                        && bc1_vec[i]
                            .correct_key_proof
                            .verify(&bc1_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                            .is_ok()
                        && bc1_vec[i].e.n.bit_length() >= PAILLIER_MIN_BIT_LENGTH
                        && bc1_vec[i].e.n.bit_length() <= PAILLIER_MAX_BIT_LENGTH
                        && bc1_vec[i].dlog_statement.N.bit_length() >= PAILLIER_MIN_BIT_LENGTH
                        && bc1_vec[i].dlog_statement.N.bit_length() <= PAILLIER_MAX_BIT_LENGTH
                        && bc1_vec[i]
                            .composite_dlog_proof_base_h1
                            .verify(&bc1_vec[i].dlog_statement)
                            .is_ok()
                        && bc1_vec[i]
                            .composite_dlog_proof_base_h2
                            .verify(&dlog_statement_base_h2)
                            .is_ok();
                if !test_res {
                    bad_actors_vec.push(i);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);

        let err_type = ErrorType {
            error_type: "invalid key".to_string(),
            bad_actors: bad_actors_vec,
        };

        let (vss_scheme, secret_shares) =
            VerifiableSS::share(params.threshold, params.share_count, &self.u_i);
        if correct_key_correct_decom_all {
            Ok((vss_scheme, secret_shares.to_vec(), self.party_index))
        } else {
            Err(err_type)
        }
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: &Parameters,
        y_vec: &[Point<Secp256k1>],
        secret_shares_vec: &[Scalar<Secp256k1>],
        vss_scheme_vec: &[VerifiableSS<Secp256k1>],
        index: usize,
    ) -> Result<(SharedKeys, DLogProof<Secp256k1, Sha256>), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(secret_shares_vec.len(), usize::from(params.share_count));
        assert_eq!(vss_scheme_vec.len(), usize::from(params.share_count));

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                let res = vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], index.try_into().unwrap())
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0] == y_vec[i];
                if !res {
                    bad_actors_vec.push(i);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);

        let err_type = ErrorType {
            error_type: "invalid vss".to_string(),
            bad_actors: bad_actors_vec,
        };

        if correct_ss_verify {
            let (head, tail) = y_vec.split_at(1);
            let y = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

            let x_i = secret_shares_vec
                .iter()
                .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
            let dlog_proof = DLogProof::prove(&x_i);
            Ok((SharedKeys { y, x_i }, dlog_proof))
        } else {
            Err(err_type)
        }
    }

    pub fn get_commitments_to_xi(
        vss_scheme_vec: &[VerifiableSS<Secp256k1>],
    ) -> Vec<Point<Secp256k1>> {
        let len = vss_scheme_vec.len();
        let (head, tail) = vss_scheme_vec.split_at(1);
        let mut global_coefficients = head[0].commitments.clone();
        for vss in tail {
            for (i, coefficient_commitment) in vss.commitments.iter().enumerate() {
                global_coefficients[i] = &global_coefficients[i] + &*coefficient_commitment;
            }
        }

        let global_vss = VerifiableSS {
            parameters: vss_scheme_vec[0].parameters.clone(),
            commitments: global_coefficients,
        };
        (1..=len)
            .map(|i| global_vss.get_point_commitment(i.try_into().unwrap()))
            .collect::<Vec<Point<Secp256k1>>>()
    }

    pub fn update_commitments_to_xi(
        comm: &Point<Secp256k1>,
        vss_scheme: &VerifiableSS<Secp256k1>,
        index: usize,
        s: &[usize],
    ) -> Point<Secp256k1> {
        let s: Vec<u16> = s.iter().map(|&i| i.try_into().unwrap()).collect();
        let li = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &vss_scheme.parameters,
            index.try_into().unwrap(),
            s.as_slice(),
        );
        comm * &li
    }

    pub fn verify_dlog_proofs_check_against_vss(
        params: &Parameters,
        dlog_proofs_vec: &[DLogProof<Secp256k1, Sha256>],
        y_vec: &[Point<Secp256k1>],
        vss_vec: &[VerifiableSS<Secp256k1>],
    ) -> Result<(), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(dlog_proofs_vec.len(), usize::from(params.share_count));
        let xi_commitments = Keys::get_commitments_to_xi(vss_vec);
        let xi_dlog_verify = (0..y_vec.len())
            .map(|i| {
                let ver_res = DLogProof::verify(&dlog_proofs_vec[i]).is_ok();
                let verify_against_vss = xi_commitments[i] == dlog_proofs_vec[i].pk;
                if !ver_res || !verify_against_vss {
                    bad_actors_vec.push(i);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);

        let err_type = ErrorType {
            error_type: "bad dlog proof".to_string(),
            bad_actors: bad_actors_vec,
        };

        if xi_dlog_verify {
            Ok(())
        } else {
            Err(err_type)
        }
    }
}

impl PartyPrivate {
    pub fn set_private(key: Keys, shared_key: SharedKeys) -> Self {
        Self {
            u_i: key.u_i,
            x_i: shared_key.x_i,
            dk: key.dk,
        }
    }

    pub fn y_i(&self) -> Point<Secp256k1> {
        let g = Point::generator();
        g * &self.u_i
    }

    pub fn decrypt(&self, ciphertext: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.dk, &RawCiphertext::from(ciphertext))
    }

    pub fn refresh_private_key(&self, factor: &Scalar<Secp256k1>, index: usize) -> Keys {
        let u: Scalar<Secp256k1> = &self.u_i + factor;
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();

        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn refresh_private_key_safe_prime(&self, factor: &Scalar<Secp256k1>, index: usize) -> Keys {
        let u: Scalar<Secp256k1> = &self.u_i + factor;
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: usize,
        num_of_segments: usize,
        pub_ke_y: &Point<Secp256k1>,
        g: &Point<Secp256k1>,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.u_i, &segment_size, num_of_segments, pub_ke_y, g)
    }

    pub fn update_private_key(
        &self,
        factor_u_i: &Scalar<Secp256k1>,
        factor_x_i: &Scalar<Secp256k1>,
    ) -> Self {
        PartyPrivate {
            u_i: &self.u_i + factor_u_i,
            x_i: &self.x_i + factor_x_i,
            dk: self.dk.clone(),
        }
    }
}

impl SignKeys {
    pub fn g_w_vec(
        pk_vec: &[Point<Secp256k1>],
        s: &[usize],
        vss_scheme: &VerifiableSS<Secp256k1>,
    ) -> Vec<Point<Secp256k1>> {
        let s: Vec<u16> = s.iter().map(|&i| i.try_into().unwrap()).collect();
        // TODO: check bounds
        (0..s.len())
            .map(|i| {
                let li = VerifiableSS::<Secp256k1>::map_share_to_new_params(
                    &vss_scheme.parameters,
                    s[i],
                    s.as_slice(),
                );
                &pk_vec[s[i] as usize] * &li
            })
            .collect::<Vec<Point<Secp256k1>>>()
    }

    pub fn create(
        private_x_i: &Scalar<Secp256k1>,
        vss_scheme: &VerifiableSS<Secp256k1>,
        index: usize,
        s: &[usize],
    ) -> Self {
        let s: Vec<u16> = s.iter().map(|&i| i.try_into().unwrap()).collect();
        let li = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &vss_scheme.parameters,
            index.try_into().unwrap(),
            s.as_slice(),
        );
        let w_i = li * private_x_i;
        let g = Point::generator();
        let g_w_i = g * &w_i;
        let gamma_i = Scalar::<Secp256k1>::random();
        let g_gamma_i = g * &gamma_i;
        let k_i = Scalar::<Secp256k1>::random();
        Self {
            w_i,
            g_w_i,
            k_i,
            gamma_i,
            g_gamma_i,
        }
    }

    pub fn phase1_broadcast(&self) -> (SignBroadcastPhase1, SignDecommitPhase1) {
        let blind_factor = BigInt::sample(SECURITY);
        let g = Point::generator();
        let g_gamma_i = g * &self.gamma_i;
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(g_gamma_i.to_bytes(true).as_ref()),
            &blind_factor,
        );

        (
            SignBroadcastPhase1 { com },
            SignDecommitPhase1 {
                blind_factor,
                g_gamma_i: self.g_gamma_i.clone(),
            },
        )
    }

    pub fn phase2_delta_i(
        &self,
        alpha_vec: &[Scalar<Secp256k1>],
        beta_vec: &[Scalar<Secp256k1>],
    ) -> Scalar<Secp256k1> {
        let vec_len = alpha_vec.len();
        assert_eq!(alpha_vec.len(), beta_vec.len());
        // assert_eq!(alpha_vec.len(), self.s.len() - 1);
        let ki_gamma_i = &self.k_i * &self.gamma_i;

        (0..vec_len)
            .map(|i| &alpha_vec[i] + &beta_vec[i])
            .fold(ki_gamma_i, |acc, x| acc + x)
    }

    pub fn phase2_sigma_i(
        &self,
        miu_vec: &[Scalar<Secp256k1>],
        ni_vec: &[Scalar<Secp256k1>],
    ) -> Scalar<Secp256k1> {
        let vec_len = miu_vec.len();
        assert_eq!(miu_vec.len(), ni_vec.len());
        //assert_eq!(miu_vec.len(), self.s.len() - 1);
        let ki_w_i = &self.k_i * &self.w_i;
        (0..vec_len)
            .map(|i| &miu_vec[i] + &ni_vec[i])
            .fold(ki_w_i, |acc, x| acc + x)
    }

    pub fn phase3_compute_t_i(
        sigma_i: &Scalar<Secp256k1>,
    ) -> (
        Point<Secp256k1>,
        Scalar<Secp256k1>,
        PedersenProof<Secp256k1, Sha256>,
    ) {
        let g_sigma_i = Point::generator() * sigma_i;
        let l = Scalar::<Secp256k1>::random();
        let h_l = Point::<Secp256k1>::base_point2() * &l;
        let T = g_sigma_i + h_l;
        let T_zk_proof = PedersenProof::<Secp256k1, Sha256>::prove(sigma_i, &l);

        (T, l, T_zk_proof)
    }
    pub fn phase3_reconstruct_delta(delta_vec: &[Scalar<Secp256k1>]) -> Scalar<Secp256k1> {
        let sum = delta_vec
            .iter()
            .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
        sum.invert().unwrap()
    }

    pub fn phase4(
        delta_inv: &Scalar<Secp256k1>,
        b_proof_vec: &[&DLogProof<Secp256k1, Sha256>],
        phase1_decommit_vec: Vec<SignDecommitPhase1>,
        bc1_vec: &[SignBroadcastPhase1],
        index: usize,
    ) -> Result<Point<Secp256k1>, ErrorType> {
        let mut bad_actors_vec = Vec::new();
        let test_b_vec_and_com = (0..b_proof_vec.len())
            .map(|j| {
                let ind = if j < index { j } else { j + 1 };
                let res = b_proof_vec[j].pk == phase1_decommit_vec[ind].g_gamma_i
                    && HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                        &BigInt::from_bytes(
                            phase1_decommit_vec[ind].g_gamma_i.to_bytes(true).as_ref(),
                        ),
                        &phase1_decommit_vec[ind].blind_factor,
                    ) == bc1_vec[ind].com;
                if !res {
                    bad_actors_vec.push(ind);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);

        let mut g_gamma_i_iter = phase1_decommit_vec.iter();
        let head = g_gamma_i_iter.next().unwrap();
        let tail = g_gamma_i_iter;

        let err_type = ErrorType {
            error_type: "bad gamma_i decommit".to_string(),
            bad_actors: bad_actors_vec,
        };

        if test_b_vec_and_com {
            Ok({
                let gamma_sum = tail.fold(head.g_gamma_i.clone(), |acc, x| acc + &x.g_gamma_i);
                // R
                gamma_sum * delta_inv
            })
        } else {
            Err(err_type)
        }
    }
}

impl LocalSignature {
    pub fn phase5_proof_pdl(
        R_dash: &Point<Secp256k1>,
        R: &Point<Secp256k1>,
        k_ciphertext: &BigInt,
        ek: &EncryptionKey,
        k_i: &Scalar<Secp256k1>,
        k_enc_randomness: &BigInt,
        dlog_statement: &DLogStatement,
    ) -> PDLwSlackProof {
        // Generate PDL with slack statement, witness and proof
        let pdl_w_slack_statement = PDLwSlackStatement {
            ciphertext: k_ciphertext.clone(),
            ek: ek.clone(),
            Q: R_dash.clone(),
            G: R.clone(),
            h1: dlog_statement.g.clone(),
            h2: dlog_statement.ni.clone(),
            N_tilde: dlog_statement.N.clone(),
        };

        let pdl_w_slack_witness = PDLwSlackWitness {
            x: k_i.clone(),
            r: k_enc_randomness.clone(),
        };

        PDLwSlackProof::prove(&pdl_w_slack_witness, &pdl_w_slack_statement)
    }

    pub fn phase5_verify_pdl(
        pdl_w_slack_proof_vec: &[PDLwSlackProof],
        R_dash: &Point<Secp256k1>,
        R: &Point<Secp256k1>,
        k_ciphertext: &BigInt,
        ek: &EncryptionKey,
        dlog_statement: &[DLogStatement],
        s: &[usize],
        i: usize,
    ) -> Result<(), ErrorType> {
        let mut bad_actors_vec = Vec::new();

        let num_of_other_participants = s.len() - 1;
        if pdl_w_slack_proof_vec.len() != num_of_other_participants {
            bad_actors_vec.push(i);
        } else {
            let proofs_verification = (0..pdl_w_slack_proof_vec.len())
                .map(|j| {
                    let ind = if j < i { j } else { j + 1 };
                    let pdl_w_slack_statement = PDLwSlackStatement {
                        ciphertext: k_ciphertext.clone(),
                        ek: ek.clone(),
                        Q: R_dash.clone(),
                        G: R.clone(),
                        h1: dlog_statement[s[ind]].g.clone(),
                        h2: dlog_statement[s[ind]].ni.clone(),
                        N_tilde: dlog_statement[s[ind]].N.clone(),
                    };
                    let ver_res = pdl_w_slack_proof_vec[j].verify(&pdl_w_slack_statement);
                    if ver_res.is_err() {
                        bad_actors_vec.push(i);
                        false
                    } else {
                        true
                    }
                })
                .all(|x| x);
            if proofs_verification {
                return Ok(());
            }
        }

        let err_type = ErrorType {
            error_type: "Bad PDLwSlack proof".to_string(),
            bad_actors: bad_actors_vec,
        };
        Err(err_type)
    }

    pub fn phase5_check_R_dash_sum(R_dash_vec: &[Point<Secp256k1>]) -> Result<(), Error> {
        let sum = R_dash_vec
            .iter()
            .fold(Point::generator().to_point(), |acc, x| acc + x);
        match sum - &Point::generator().to_point() == Point::generator().to_point() {
            true => Ok(()),
            false => Err(Phase5BadSum),
        }
    }

    pub fn phase6_compute_S_i_and_proof_of_consistency(
        R: &Point<Secp256k1>,
        T: &Point<Secp256k1>,
        sigma: &Scalar<Secp256k1>,
        l: &Scalar<Secp256k1>,
    ) -> (Point<Secp256k1>, HomoELGamalProof<Secp256k1, Sha256>) {
        let S = R * sigma;
        let delta = HomoElGamalStatement {
            G: R.clone(),
            H: Point::<Secp256k1>::base_point2().clone(),
            Y: Point::generator().to_point(),
            D: T.clone(),
            E: S.clone(),
        };
        let witness = HomoElGamalWitness {
            x: l.clone(),
            r: sigma.clone(),
        };
        let proof = HomoELGamalProof::prove(&witness, &delta);

        (S, proof)
    }

    pub fn phase6_verify_proof(
        S_vec: &[Point<Secp256k1>],
        proof_vec: &[HomoELGamalProof<Secp256k1, Sha256>],
        R_vec: &[Point<Secp256k1>],
        T_vec: &[Point<Secp256k1>],
    ) -> Result<(), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        let mut verify_proofs = true;
        for i in 0..proof_vec.len() {
            let delta = HomoElGamalStatement {
                G: R_vec[i].clone(),
                H: Point::<Secp256k1>::base_point2().clone(),
                Y: Point::generator().to_point(),
                D: T_vec[i].clone(),
                E: S_vec[i].clone(),
            };
            if proof_vec[i].verify(&delta).is_err() {
                verify_proofs = false;
                bad_actors_vec.push(i);
            };
        }

        match verify_proofs {
            true => Ok(()),
            false => {
                let err_type = ErrorType {
                    error_type: "phase6".to_string(),
                    bad_actors: bad_actors_vec,
                };
                Err(err_type)
            }
        }
    }

    pub fn phase6_check_S_i_sum(
        pubkey_y: &Point<Secp256k1>,
        S_vec: &[Point<Secp256k1>],
    ) -> Result<(), Error> {
        let sum_plus_g = S_vec
            .iter()
            .fold(Point::generator().to_point(), |acc, x| acc + x);
        let sum = sum_plus_g - &Point::generator().to_point();

        match &sum == pubkey_y {
            true => Ok(()),
            false => Err(Phase6Error),
        }
    }

    pub fn phase7_local_sig(
        k_i: &Scalar<Secp256k1>,
        message: &BigInt,
        R: &Point<Secp256k1>,
        sigma_i: &Scalar<Secp256k1>,
        pubkey: &Point<Secp256k1>,
    ) -> Self {
        let m_fe = Scalar::<Secp256k1>::from(message);
        let r = Scalar::<Secp256k1>::from(
            &R.x_coord()
                .unwrap()
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let s_i = m_fe * k_i + &r * sigma_i;
        Self {
            r,
            R: R.clone(),
            s_i,
            m: message.clone(),
            y: pubkey.clone(),
        }
    }

    pub fn output_signature(&self, s_vec: &[Scalar<Secp256k1>]) -> Result<SignatureRecid, Error> {
        let mut s = s_vec.iter().fold(self.s_i.clone(), |acc, x| acc + x);
        let s_bn = s.to_bigint();

        let r = Scalar::<Secp256k1>::from(
            &self
                .R
                .x_coord()
                .unwrap()
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let ry: BigInt = self
            .R
            .y_coord()
            .unwrap()
            .mod_floor(Scalar::<Secp256k1>::group_order());

        /*
         Calculate recovery id - it is not possible to compute the public key out of the signature
         itself. Recovery id is used to enable extracting the public key uniquely.
         1. id = R.y & 1
         2. if (s > curve.q / 2) id = id ^ 1
        */
        let is_ry_odd = ry.test_bit(0);
        let mut recid = if is_ry_odd { 1 } else { 0 };
        let s_tag_bn = Scalar::<Secp256k1>::group_order() - &s_bn;
        if s_bn > s_tag_bn {
            s = Scalar::<Secp256k1>::from(&s_tag_bn);
            recid ^= 1;
        }
        let sig = SignatureRecid { r, s, recid };
        let ver = verify(&sig, &self.y, &self.m).is_ok();
        if ver {
            Ok(sig)
        } else {
            Err(InvalidSig)
        }
    }
}

pub fn verify(sig: &SignatureRecid, y: &Point<Secp256k1>, message: &BigInt) -> Result<(), Error> {
    let b = sig.s.invert().unwrap();
    let a = Scalar::<Secp256k1>::from(message);
    let u1 = a * &b;
    let u2 = &sig.r * &b;

    let g = Point::generator();
    let gu1 = g * u1;
    let yu2 = y * &u2;
    // can be faster using shamir trick

    if sig.r
        == Scalar::<Secp256k1>::from(
            &(gu1 + yu2)
                .x_coord()
                .unwrap()
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        )
    {
        Ok(())
    } else {
        Err(InvalidSig)
    }
}
