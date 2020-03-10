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
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};

use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NICorrectKeyProof;

use crate::Error::{self, InvalidCom, InvalidKey, InvalidSS, InvalidSig};

const SECURITY: usize = 256;

#[derive(Debug)]
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
    pub com: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
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
    pub l_i: FE,
    pub rho_i: FE,
    pub R: GE,
    pub s_i: FE,
    pub m: BigInt,
    pub y: GE,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase5Com1 {
    pub com: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase5Com2 {
    pub com: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase5ADecom1 {
    pub V_i: GE,
    pub A_i: GE,
    pub B_i: GE,
    pub blind_factor: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase5DDecom2 {
    pub u_i: GE,
    pub t_i: GE,
    pub blind_factor: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub r: FE,
    pub s: FE,
    pub recid: u8,
}

impl Keys {
    pub fn create(index: usize) -> Self {
        let u = FE::new_random();
        let y = GE::generator() * u;
        let (ek, dk) = Paillier::keypair().keys();

        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn create_safe_prime(index: usize) -> Keys {
        let u: FE = ECScalar::new_random();
        let y = &ECPoint::generator() * &u;

        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index.clone(),
        }
    }
    pub fn create_from(u: FE, index: usize) -> Keys {
        let y = &ECPoint::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();

        Self {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    pub fn phase1_broadcast_phase3_proof_of_correct_key(
        &self,
    ) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        let blind_factor = BigInt::sample(SECURITY);
        let correct_key_proof = NICorrectKeyProof::proof(&self.dk);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &self.y_i.bytes_compressed_to_big_int(),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 {
            e: self.ek.clone(),
            com,
            correct_key_proof,
        };
        let decom1 = KeyGenDecommitMessage1 {
            blind_factor,
            y_i: self.y_i,
        };
        (bcm1, decom1)
    }

    pub fn phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
        &self,
        params: &Parameters,
        decom_vec: &[KeyGenDecommitMessage1],
        bc1_vec: &[KeyGenBroadcastMessage1],
    ) -> Result<(VerifiableSS, Vec<FE>, usize), Error> {
        // test length:
        assert_eq!(decom_vec.len() as u16, params.share_count);
        assert_eq!(bc1_vec.len() as u16, params.share_count);
        // test paillier correct key and test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::create_commitment_with_user_defined_randomness(
                    &decom_vec[i].y_i.bytes_compressed_to_big_int(),
                    &decom_vec[i].blind_factor,
                ) == bc1_vec[i].com
                    && bc1_vec[i].correct_key_proof.verify(&bc1_vec[i].e).is_ok()
            })
            .all(|x| x);

        let (vss_scheme, secret_shares) = VerifiableSS::share(
            params.threshold as usize,
            params.share_count as usize,
            &self.u_i,
        );
        if correct_key_correct_decom_all {
            Ok((vss_scheme, secret_shares, self.party_index))
        } else {
            Err(InvalidKey)
        }
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: &Parameters,
        y_vec: &[GE],
        secret_shares_vec: &[FE],
        vss_scheme_vec: &[VerifiableSS],
        index: usize,
    ) -> Result<(SharedKeys, DLogProof), Error> {
        assert_eq!(y_vec.len() as u16, params.share_count);
        assert_eq!(secret_shares_vec.len() as u16, params.share_count);
        assert_eq!(vss_scheme_vec.len() as u16, params.share_count);

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0].get_element() == y_vec[i].get_element()
            })
            .all(|x| x);

        if correct_ss_verify {
            let (head, tail) = y_vec.split_at(1);
            let y = tail.iter().fold(head[0], |acc, x| acc + x);

            let x_i = secret_shares_vec.iter().fold(FE::zero(), |acc, x| acc + x);
            let dlog_proof = DLogProof::prove(&x_i);
            Ok((SharedKeys { y, x_i }, dlog_proof))
        } else {
            Err(InvalidSS)
        }
    }

    pub fn get_commitments_to_xi(vss_scheme_vec: &[VerifiableSS]) -> Vec<GE> {
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
        vss_scheme: &VerifiableSS,
        index: usize,
        s: &[usize],
    ) -> GE {
        let li = vss_scheme.map_share_to_new_params(index, s);
        comm * &li
    }

    pub fn verify_dlog_proofs(
        params: &Parameters,
        dlog_proofs_vec: &[DLogProof],
        y_vec: &[GE],
    ) -> Result<(), Error> {
        assert_eq!(y_vec.len() as u16, params.share_count);
        assert_eq!(dlog_proofs_vec.len() as u16, params.share_count);
        let xi_dlog_verify = (0..y_vec.len())
            .map(|i| DLogProof::verify(&dlog_proofs_vec[i]).is_ok())
            .all(|x| x);

        if xi_dlog_verify {
            Ok(())
        } else {
            Err(InvalidKey)
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

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn refresh_private_key_safe_prime(&self, factor: &FE, index: usize) -> Keys {
        let u: FE = self.u_i + factor;
        let y = &ECPoint::generator() * &u;
        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index.clone(),
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
    pub fn create(
        private: &PartyPrivate,
        vss_scheme: &VerifiableSS,
        index: usize,
        s: &[usize],
    ) -> Self {
        let li = vss_scheme.map_share_to_new_params(index, s);
        let w_i = li * private.x_i;
        let g: GE = ECPoint::generator();
        let g_w_i = g * w_i;
        let gamma_i: FE = ECScalar::new_random();
        let g_gamma_i = g * gamma_i;

        Self {
            w_i,
            g_w_i,
            k_i: ECScalar::new_random(),
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

    pub fn phase3_reconstruct_delta(delta_vec: &[FE]) -> FE {
        let sum = delta_vec.iter().fold(FE::zero(), |acc, x| acc + x);
        sum.invert()
    }

    pub fn phase4(
        delta_inv: &FE,
        b_proof_vec: &[&DLogProof],
        phase1_decommit_vec: Vec<SignDecommitPhase1>,
        bc1_vec: &[SignBroadcastPhase1],
    ) -> Result<GE, Error> {
        // note: b_proof_vec is populated using the results
        //from the MtAwc, which is handling the proof of knowledge verification of gamma_i such that
        // Gamme_i = gamma_i * G in the verify_proofs_get_alpha()
        let test_b_vec_and_com = (0..b_proof_vec.len())
            .map(|i| {
                b_proof_vec[i].pk.get_element() == phase1_decommit_vec[i].g_gamma_i.get_element()
                    && HashCommitment::create_commitment_with_user_defined_randomness(
                        &phase1_decommit_vec[i]
                            .g_gamma_i
                            .bytes_compressed_to_big_int(),
                        &phase1_decommit_vec[i].blind_factor,
                    ) == bc1_vec[i].com
            })
            .all(|x| x);

        let mut g_gamma_i_iter = phase1_decommit_vec.iter();
        let head = g_gamma_i_iter.next().unwrap();
        let tail = g_gamma_i_iter;
        if test_b_vec_and_com {
            Ok({
                let gamma_sum = tail.fold(head.g_gamma_i, |acc, x| acc + x.g_gamma_i);
                // R
                gamma_sum * delta_inv
            })
        } else {
            Err(InvalidKey)
        }
    }
}

impl LocalSignature {
    pub fn phase5_local_sig(k_i: &FE, message: &BigInt, R: &GE, sigma_i: &FE, pubkey: &GE) -> Self {
        let m_fe: FE = ECScalar::from(message);
        let r: FE = ECScalar::from(&R.x_coor().unwrap().mod_floor(&FE::q()));
        let s_i = m_fe * k_i + r * sigma_i;
        let l_i: FE = ECScalar::new_random();
        let rho_i: FE = ECScalar::new_random();
        Self {
            l_i,
            rho_i,
            R: *R,
            s_i,
            m: message.clone(),
            y: *pubkey,
        }
    }

    pub fn phase5a_broadcast_5b_zkproof(
        &self,
    ) -> (Phase5Com1, Phase5ADecom1, HomoELGamalProof, DLogProof) {
        let blind_factor = BigInt::sample(SECURITY);
        let g: GE = ECPoint::generator();
        let A_i = g * self.rho_i;
        let l_i_rho_i = self.l_i.mul(&self.rho_i.get_element());
        let B_i = g * l_i_rho_i;
        let V_i = self.R * self.s_i + g * self.l_i;
        let input_hash = HSha256::create_hash_from_ge(&[&V_i, &A_i, &B_i]).to_big_int();
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &input_hash,
            &blind_factor,
        );
        let witness = HomoElGamalWitness {
            r: self.l_i,
            x: self.s_i,
        };
        let delta = HomoElGamalStatement {
            G: A_i,
            H: self.R,
            Y: g,
            D: V_i,
            E: B_i,
        };
        let dlog_proof_rho = DLogProof::prove(&self.rho_i);
        let proof = HomoELGamalProof::prove(&witness, &delta);

        (
            Phase5Com1 { com },
            Phase5ADecom1 {
                V_i,
                A_i,
                B_i,
                blind_factor,
            },
            proof,
            dlog_proof_rho,
        )
    }

    pub fn phase5c(
        &self,
        decom_vec: &[Phase5ADecom1],
        com_vec: &[Phase5Com1],
        elgamal_proofs: &[HomoELGamalProof],
        dlog_proofs_rho: &[DLogProof],
        v_i: &GE,
        R: &GE,
    ) -> Result<(Phase5Com2, Phase5DDecom2), Error> {
        assert_eq!(decom_vec.len(), com_vec.len());

        let g: GE = ECPoint::generator();
        let test_com_elgamal = (0..com_vec.len())
            .map(|i| {
                let delta = HomoElGamalStatement {
                    G: decom_vec[i].A_i,
                    H: *R,
                    Y: g,
                    D: decom_vec[i].V_i,
                    E: decom_vec[i].B_i,
                };
                let input_hash = HSha256::create_hash_from_ge(&[
                    &decom_vec[i].V_i,
                    &decom_vec[i].A_i,
                    &decom_vec[i].B_i,
                ])
                .to_big_int();

                HashCommitment::create_commitment_with_user_defined_randomness(
                    &input_hash,
                    &decom_vec[i].blind_factor,
                ) == com_vec[i].com
                    && elgamal_proofs[i].verify(&delta).is_ok()
                    && DLogProof::verify(&dlog_proofs_rho[i]).is_ok()
            })
            .all(|x| x);

        let v_vec = (0..com_vec.len())
            .map(|i| &decom_vec[i].V_i)
            .collect::<Vec<&GE>>();
        let a_vec = (0..com_vec.len())
            .map(|i| &decom_vec[i].A_i)
            .collect::<Vec<&GE>>();

        let v = v_vec.iter().fold(v_i.clone(), |acc, x| acc + *x);
        // V = -mG -ry - sum (vi)
        let mut a_i_iter = a_vec.iter();
        let head = a_i_iter.next().unwrap();
        let tail = a_i_iter;
        let a = tail.fold((*head).clone(), |acc, x| acc.add_point(&(*x).get_element()));

        let r: FE = ECScalar::from(&self.R.x_coor().unwrap().mod_floor(&FE::q()));
        let yr = self.y * r;
        let g: GE = ECPoint::generator();
        let m_fe: FE = ECScalar::from(&self.m);
        let gm = g * m_fe;
        let v = v.sub_point(&gm.get_element()).sub_point(&yr.get_element());
        let u_i = v * self.rho_i;
        let t_i = a * self.l_i;
        let input_hash = HSha256::create_hash_from_ge(&[&u_i, &t_i]).to_big_int();
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &input_hash,
            &blind_factor,
        );

        if test_com_elgamal {
            Ok({
                (
                    Phase5Com2 { com },
                    Phase5DDecom2 {
                        u_i,
                        t_i,
                        blind_factor,
                    },
                )
            })
        } else {
            Err(InvalidCom)
        }
    }

    pub fn phase5d(
        &self,
        decom_vec2: &[Phase5DDecom2],
        com_vec2: &[Phase5Com2],
        decom_vec1: &[Phase5ADecom1],
    ) -> Result<FE, Error> {
        assert_eq!(decom_vec2.len(), decom_vec1.len());
        assert_eq!(decom_vec2.len(), com_vec2.len());

        let test_com = (0..com_vec2.len())
            .map(|i| {
                let input_hash =
                    HSha256::create_hash_from_ge(&[&decom_vec2[i].u_i, &decom_vec2[i].t_i])
                        .to_big_int();
                HashCommitment::create_commitment_with_user_defined_randomness(
                    &input_hash,
                    &decom_vec2[i].blind_factor,
                ) == com_vec2[i].com
            })
            .all(|x| x);

        let t_vec = (0..com_vec2.len())
            .map(|i| &decom_vec2[i].t_i)
            .collect::<Vec<&GE>>();
        let u_vec = (0..com_vec2.len())
            .map(|i| &decom_vec2[i].u_i)
            .collect::<Vec<&GE>>();
        let b_vec = (0..decom_vec1.len())
            .map(|i| &decom_vec1[i].B_i)
            .collect::<Vec<&GE>>();

        let g: GE = ECPoint::generator();
        let biased_sum_tb = t_vec.iter().zip(b_vec).fold(g, |acc, x| acc + *x.0 + x.1);
        let biased_sum_tb_minus_u = u_vec
            .iter()
            .fold(biased_sum_tb, |acc, x| acc.sub_point(&x.get_element()));
        if test_com {
            if g == biased_sum_tb_minus_u {
                Ok(self.s_i)
            } else {
                Err(InvalidKey)
            }
        } else {
            Err(InvalidCom)
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
        let is_ry_odd = ry.tstbit(0);
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
