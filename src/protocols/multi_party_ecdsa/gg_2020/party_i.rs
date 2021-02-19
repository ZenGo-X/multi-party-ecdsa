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
use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use curv::BigInt;

use crate::Error::{self, InvalidSig, Phase5BadSum, Phase6Error};
use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};

use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NICorrectKeyProof;
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

use crate::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use crate::utilities::zk_pdl_with_slack::{PDLwSlackProof, PDLwSlackStatement, PDLwSlackWitness};

const SECURITY: usize = 256;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keys {
    pub u_i: FE,
    pub y_i: GE,
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub party_index: usize,
    pub N_tilde: BigInt,
    pub h1: BigInt,
    pub h2: BigInt,
    pub xhi: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyPrivate {
    u_i: FE,
    x_i: FE,
    dk: DecryptionKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenBroadcastMessage1 {
    pub e: EncryptionKey,
    pub dlog_statement: DLogStatement,
    pub com: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
    pub composite_dlog_proof: CompositeDLogProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage1 {
    pub blind_factor: BigInt,
    pub y_i: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: GE,
    pub x_i: FE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignKeys {
    pub w_i: FE,
    pub g_w_i: GE,
    pub k_i: FE,
    pub gamma_i: FE,
    pub g_gamma_i: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignBroadcastPhase1 {
    pub com: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignDecommitPhase1 {
    pub blind_factor: BigInt,
    pub g_gamma_i: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSignature {
    pub r: FE,
    pub R: GE,
    pub s_i: FE,
    pub m: BigInt,
    pub y: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub r: FE,
    pub s: FE,
    pub recid: u8,
}

pub fn generate_h1_h2_N_tilde() -> (BigInt, BigInt, BigInt, BigInt) {
    //note, should be safe primes:
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();;
    let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
    let one = BigInt::one();
    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    let h1 = BigInt::sample_below(&phi);
    let S = BigInt::from(2).pow(256 as u32);
    let xhi = BigInt::sample_below(&S);
    let h1_inv = BigInt::mod_inv(&h1, &ek_tilde.n).unwrap();
    let h2 = BigInt::mod_pow(&h1_inv, &xhi, &ek_tilde.n);

    (ek_tilde.n, h1, h2, xhi)
}

impl Keys {
    pub fn create(index: usize) -> Self {
        let u = FE::new_random();
        let y = GE::generator() * u;
        let (ek, dk) = Paillier::keypair().keys();
        let (N_tilde, h1, h2, xhi) = generate_h1_h2_N_tilde();

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
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn create_safe_prime(index: usize) -> Keys {
        let u: FE = ECScalar::new_random();
        let y = &ECPoint::generator() * &u;

        let (ek, dk) = Paillier::keypair_safe_primes().keys();
        let (N_tilde, h1, h2, xhi) = generate_h1_h2_N_tilde();

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
        }
    }
    pub fn create_from(u: FE, index: usize) -> Keys {
        let y = &ECPoint::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();
        let (N_tilde, h1, h2, xhi) = generate_h1_h2_N_tilde();

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
        }
    }

    pub fn phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2(
        &self,
    ) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        let blind_factor = BigInt::sample(SECURITY);
        let correct_key_proof = NICorrectKeyProof::proof(&self.dk, None);

        let dlog_statement = DLogStatement {
            N: self.N_tilde.clone(),
            g: self.h1.clone(),
            ni: self.h2.clone(),
        };

        let composite_dlog_proof = CompositeDLogProof::prove(&dlog_statement, &self.xhi);

        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &self.y_i.bytes_compressed_to_big_int(),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 {
            e: self.ek.clone(),
            dlog_statement,
            com,
            correct_key_proof,
            composite_dlog_proof,
        };
        let decom1 = KeyGenDecommitMessage1 {
            blind_factor,
            y_i: self.y_i,
        };
        (bcm1, decom1)
    }

    pub fn phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
        &self,
        params: &Parameters,
        decom_vec: &[KeyGenDecommitMessage1],
        bc1_vec: &[KeyGenBroadcastMessage1],
    ) -> Result<(VerifiableSS<GE>, Vec<FE>, usize), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        // test length:
        assert_eq!(decom_vec.len() as u16, params.share_count);
        assert_eq!(bc1_vec.len() as u16, params.share_count);
        // test paillier correct key, h1,h2 correct generation and test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                let test_res = HashCommitment::create_commitment_with_user_defined_randomness(
                    &decom_vec[i].y_i.bytes_compressed_to_big_int(),
                    &decom_vec[i].blind_factor,
                ) == bc1_vec[i].com
                    && bc1_vec[i]
                        .correct_key_proof
                        .verify(&bc1_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                        .is_ok()
                    && bc1_vec[i]
                        .composite_dlog_proof
                        .verify(&bc1_vec[i].dlog_statement)
                        .is_ok();
                if test_res == false {
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

        let (vss_scheme, secret_shares) = VerifiableSS::share(
            params.threshold as usize,
            params.share_count as usize,
            &self.u_i,
        );
        if correct_key_correct_decom_all {
            Ok((vss_scheme, secret_shares, self.party_index))
        } else {
            Err(err_type)
        }
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: &Parameters,
        y_vec: &[GE],
        secret_shares_vec: &[FE],
        vss_scheme_vec: &[VerifiableSS<GE>],
        index: usize,
    ) -> Result<(SharedKeys, DLogProof<GE>), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        assert_eq!(y_vec.len() as u16, params.share_count);
        assert_eq!(secret_shares_vec.len() as u16, params.share_count);
        assert_eq!(vss_scheme_vec.len() as u16, params.share_count);

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                let res = vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0].get_element() == y_vec[i].get_element();
                if res == false {
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
            let y = tail.iter().fold(head[0], |acc, x| acc + x);

            let x_i = secret_shares_vec.iter().fold(FE::zero(), |acc, x| acc + x);
            let dlog_proof = DLogProof::prove(&x_i);
            Ok((SharedKeys { y, x_i }, dlog_proof))
        } else {
            Err(err_type)
        }
    }

    pub fn get_commitments_to_xi(vss_scheme_vec: &[VerifiableSS<GE>]) -> Vec<GE> {
        let len = vss_scheme_vec.len();
        (1..=len)
            .map(|i| {
                let xij_points_vec = (0..len)
                    .map(|j| vss_scheme_vec[j].get_point_commitment(i))
                    .collect::<Vec<GE>>();

                let mut xij_points_iter = xij_points_vec.iter();
                let first = xij_points_iter.next().unwrap();

                let tail = xij_points_iter;
                tail.fold(first.clone(), |acc, x| acc + x)
            })
            .collect::<Vec<GE>>()
    }

    pub fn update_commitments_to_xi(
        comm: &GE,
        vss_scheme: &VerifiableSS<GE>,
        index: usize,
        s: &[usize],
    ) -> GE {
        let li = VerifiableSS::<GE>::map_share_to_new_params(&vss_scheme.parameters, index, s);
        comm * &li
    }

    pub fn verify_dlog_proofs(
        params: &Parameters,
        dlog_proofs_vec: &[DLogProof<GE>],
        y_vec: &[GE],
    ) -> Result<(), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        assert_eq!(y_vec.len() as u16, params.share_count);
        assert_eq!(dlog_proofs_vec.len() as u16, params.share_count);
        let xi_dlog_verify = (0..y_vec.len())
            .map(|i| {
                let ver_res = DLogProof::verify(&dlog_proofs_vec[i]).is_ok();
                if ver_res == false {
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

    pub fn y_i(&self) -> GE {
        let g: GE = ECPoint::generator();
        g * self.u_i
    }

    pub fn decrypt(&self, ciphertext: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.dk, &RawCiphertext::from(ciphertext))
    }

    pub fn refresh_private_key(&self, factor: &FE, index: usize) -> Keys {
        let u: FE = self.u_i + factor;
        let y = GE::generator() * u;
        let (ek, dk) = Paillier::keypair().keys();

        let (N_tilde, h1, h2, xhi) = generate_h1_h2_N_tilde();

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
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn refresh_private_key_safe_prime(&self, factor: &FE, index: usize) -> Keys {
        let u: FE = self.u_i + factor;
        let y = &ECPoint::generator() * &u;
        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        let (N_tilde, h1, h2, xhi) = generate_h1_h2_N_tilde();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index.clone(),
            N_tilde,
            h1,
            h2,
            xhi,
        }
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: usize,
        num_of_segments: usize,
        pub_ke_y: &GE,
        g: &GE,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.u_i, &segment_size, num_of_segments, pub_ke_y, g)
    }

    pub fn update_private_key(&self, factor_u_i: &FE, factor_x_i: &FE) -> Self {
        PartyPrivate {
            u_i: self.u_i + factor_u_i,
            x_i: self.x_i + factor_x_i,
            dk: self.dk.clone(),
        }
    }
}

impl SignKeys {
    pub fn g_w_vec(pk_vec: &[GE], s: &[usize], vss_scheme: &VerifiableSS<GE>) -> Vec<GE> {
        // TODO: check bounds
        (0..s.len())
            .map(|i| {
                let li =
                    VerifiableSS::<GE>::map_share_to_new_params(&vss_scheme.parameters, s[i], s);
                pk_vec[s[i]] * &li
            })
            .collect::<Vec<GE>>()
    }

    pub fn create(
        private: &PartyPrivate,
        vss_scheme: &VerifiableSS<GE>,
        index: usize,
        s: &[usize],
    ) -> Self {
        let li = VerifiableSS::<GE>::map_share_to_new_params(&vss_scheme.parameters, index, s);
        let w_i = li * private.x_i;
        let g: GE = ECPoint::generator();
        let g_w_i = g * w_i;
        let gamma_i: FE = ECScalar::new_random();
        let g_gamma_i = g * gamma_i;
        let k_i: FE = ECScalar::new_random();
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
        let g: GE = ECPoint::generator();
        let g_gamma_i = g * self.gamma_i;
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &g_gamma_i.bytes_compressed_to_big_int(),
            &blind_factor,
        );

        (
            SignBroadcastPhase1 { com },
            SignDecommitPhase1 {
                blind_factor,
                g_gamma_i: self.g_gamma_i,
            },
        )
    }

    pub fn phase2_delta_i(&self, alpha_vec: &[FE], beta_vec: &[FE]) -> FE {
        let vec_len = alpha_vec.len();
        assert_eq!(alpha_vec.len(), beta_vec.len());
        // assert_eq!(alpha_vec.len(), self.s.len() - 1);
        let ki_gamma_i = self.k_i.mul(&self.gamma_i.get_element());

        (0..vec_len)
            .map(|i| alpha_vec[i].add(&beta_vec[i].get_element()))
            .fold(ki_gamma_i, |acc, x| acc + x)
    }

    pub fn phase2_sigma_i(&self, miu_vec: &[FE], ni_vec: &[FE]) -> FE {
        let vec_len = miu_vec.len();
        assert_eq!(miu_vec.len(), ni_vec.len());
        //assert_eq!(miu_vec.len(), self.s.len() - 1);
        let ki_w_i = self.k_i.mul(&self.w_i.get_element());
        (0..vec_len)
            .map(|i| miu_vec[i].add(&ni_vec[i].get_element()))
            .fold(ki_w_i, |acc, x| acc + x)
    }

    pub fn phase3_compute_t_i(sigma_i: &FE) -> (GE, FE) {
        let g_sigma_i = GE::generator() * sigma_i;
        let l: FE = ECScalar::new_random();
        let h_l = GE::base_point2() * &l;
        let T = g_sigma_i + h_l;
        (T, l)
    }
    pub fn phase3_reconstruct_delta(delta_vec: &[FE]) -> FE {
        let sum = delta_vec.iter().fold(FE::zero(), |acc, x| acc + x);
        sum.invert()
    }

    pub fn phase4(
        delta_inv: &FE,
        b_proof_vec: &[&DLogProof<GE>],
        phase1_decommit_vec: Vec<SignDecommitPhase1>,
        bc1_vec: &[SignBroadcastPhase1],
        index: usize,
    ) -> Result<GE, ErrorType> {
        let mut bad_actors_vec = Vec::new();
        let test_b_vec_and_com = (0..b_proof_vec.len())
            .map(|j| {
                let ind = if j < index { j } else { j + 1 };
                let res = b_proof_vec[j].pk.get_element()
                    == phase1_decommit_vec[ind].g_gamma_i.get_element()
                    && HashCommitment::create_commitment_with_user_defined_randomness(
                        &phase1_decommit_vec[ind]
                            .g_gamma_i
                            .bytes_compressed_to_big_int(),
                        &phase1_decommit_vec[ind].blind_factor,
                    ) == bc1_vec[ind].com;
                if res == false {
                    bad_actors_vec.push(j);
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
                let gamma_sum = tail.fold(head.g_gamma_i, |acc, x| acc + x.g_gamma_i);
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
        R_dash: &GE,
        R: &GE,
        k_ciphertext: &BigInt,
        ek: &EncryptionKey,
        k_i: &FE,
        k_enc_randomness: &BigInt,
        key: &Keys,
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
            dk: key.dk.clone(),
        };

        let proof = PDLwSlackProof::prove(&pdl_w_slack_witness, &pdl_w_slack_statement);
        proof
    }

    pub fn phase5_verify_pdl(
        pdl_w_slack_proof_vec: &[PDLwSlackProof],
        R_dash: &GE,
        R: &GE,
        k_ciphertext: &BigInt,
        ek: &EncryptionKey,
        dlog_statement: &[DLogStatement],
        s: &[usize],
        i: usize,
    ) -> Result<(), ErrorType> {
        let mut bad_actors_vec = Vec::new();

        let proofs_verification = (0..pdl_w_slack_proof_vec.len())
            .map(|j| {
                let ind = if j < i { j } else { j + 1 };
                let pdl_w_slack_statement = PDLwSlackStatement {
                    ciphertext: k_ciphertext.clone(),
                    ek: ek.clone(),
                    Q: *R_dash,
                    G: *R,
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

        let err_type = ErrorType {
            error_type: "bad gamma_i decommit".to_string(),
            bad_actors: bad_actors_vec,
        };
        if proofs_verification {
            Ok(())
        } else {
            Err(err_type)
        }
    }

    pub fn phase5_check_R_dash_sum(R_dash_vec: &[GE]) -> Result<(), Error> {
        let sum = R_dash_vec.iter().fold(GE::generator(), |acc, x| acc + x);
        match sum.sub_point(&GE::generator().get_element()) == GE::generator() {
            true => Ok(()),
            false => Err(Phase5BadSum),
        }
    }

    pub fn phase6_compute_S_i_and_proof_of_consistency(
        R: &GE,
        T: &GE,
        sigma: &FE,
        l: &FE,
    ) -> (GE, HomoELGamalProof<GE>) {
        let S = R * sigma;
        let delta = HomoElGamalStatement {
            G: R.clone(),
            H: GE::base_point2(),
            Y: GE::generator(),
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
        S_vec: &[GE],
        proof_vec: &[HomoELGamalProof<GE>],
        R_vec: &[GE],
        T_vec: &[GE],
    ) -> Result<(), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        let mut verify_proofs = true;
        for i in 0..proof_vec.len() {
            let delta = HomoElGamalStatement {
                G: R_vec[i].clone(),
                H: GE::base_point2(),
                Y: GE::generator(),
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

    pub fn phase6_check_S_i_sum(pubkey_y: &GE, S_vec: &[GE]) -> Result<(), Error> {
        let sum_plus_g = S_vec.iter().fold(GE::generator(), |acc, x| acc + x);
        let sum = sum_plus_g.sub_point(&GE::generator().get_element());

        match &sum == pubkey_y {
            true => Ok(()),
            false => Err(Phase6Error),
        }
    }

    pub fn phase7_local_sig(k_i: &FE, message: &BigInt, R: &GE, sigma_i: &FE, pubkey: &GE) -> Self {
        let m_fe: FE = ECScalar::from(message);
        let r: FE = ECScalar::from(&R.x_coor().unwrap().mod_floor(&FE::q()));
        let s_i = m_fe * k_i + r * sigma_i;
        Self {
            r,
            R: *R,
            s_i,
            m: message.clone(),
            y: *pubkey,
        }
    }

    pub fn output_signature(&self, s_vec: &[FE]) -> Result<SignatureRecid, Error> {
        let mut s = s_vec.iter().fold(self.s_i, |acc, x| acc + x);
        let s_bn = s.to_big_int();

        let r: FE = ECScalar::from(&self.R.x_coor().unwrap().mod_floor(&FE::q()));
        let ry: BigInt = self.R.y_coor().unwrap().mod_floor(&FE::q());

        /*
         Calculate recovery id - it is not possible to compute the public key out of the signature
         itself. Recovery id is used to enable extracting the public key uniquely.
         1. id = R.y & 1
         2. if (s > curve.q / 2) id = id ^ 1
        */
        let is_ry_odd = ry.test_bit(0);
        let mut recid = if is_ry_odd { 1 } else { 0 };
        let s_tag_bn = FE::q() - &s_bn;
        if s_bn > s_tag_bn {
            s = ECScalar::from(&s_tag_bn);
            recid = recid ^ 1;
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

pub fn verify(sig: &SignatureRecid, y: &GE, message: &BigInt) -> Result<(), Error> {
    let b = sig.s.invert();
    let a: FE = ECScalar::from(message);
    let u1 = a * b;
    let u2 = sig.r * b;

    let g: GE = ECPoint::generator();
    let gu1 = g * u1;
    let yu2 = y * &u2;
    // can be faster using shamir trick

    if sig.r == ECScalar::from(&(gu1 + yu2).x_coor().unwrap().mod_floor(&FE::q())) {
        Ok(())
    } else {
        Err(InvalidSig)
    }
}
