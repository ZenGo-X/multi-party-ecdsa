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

use std::convert::TryFrom;

use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Curve, Point, Scalar, Secp256k1};
use curv::BigInt;
use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};
use sha2::Sha256;
use zk_paillier::zkproofs::NiCorrectKeyProof;

use serde::{Deserialize, Serialize};

use crate::Error::{self, InvalidCom, InvalidKey, InvalidSS, InvalidSig};

const SECURITY: usize = 256;

#[derive(Debug)]
pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keys<E: Curve = Secp256k1> {
    pub u_i: Scalar<E>,
    pub y_i: Point<E>,
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub party_index: u16,
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
    pub com: BigInt,
    pub correct_key_proof: NiCorrectKeyProof,
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
    pub l_i: Scalar<Secp256k1>,
    pub rho_i: Scalar<Secp256k1>,
    pub R: Point<Secp256k1>,
    pub s_i: Scalar<Secp256k1>,
    pub m: BigInt,
    pub y: Point<Secp256k1>,
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
    pub V_i: Point<Secp256k1>,
    pub A_i: Point<Secp256k1>,
    pub B_i: Point<Secp256k1>,
    pub blind_factor: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase5DDecom2 {
    pub u_i: Point<Secp256k1>,
    pub t_i: Point<Secp256k1>,
    pub blind_factor: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub r: Scalar<Secp256k1>,
    pub s: Scalar<Secp256k1>,
    pub recid: u8,
}

impl Keys {
    pub fn create(index: u16) -> Self {
        let u = Scalar::<Secp256k1>::random();
        let y = Point::generator() * &u;
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
    pub fn create_safe_prime(index: u16) -> Keys {
        let u = Scalar::<Secp256k1>::random();
        let y = Point::generator() * &u;

        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
        }
    }
    pub fn create_from(u: Scalar<Secp256k1>, index: u16) -> Keys {
        let y = Point::generator() * &u;
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
        let correct_key_proof = NiCorrectKeyProof::proof(&self.dk, None);
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(self.y_i.to_bytes(true).as_ref()),
            &blind_factor,
        );
        let bcm1 = KeyGenBroadcastMessage1 {
            e: self.ek.clone(),
            com,
            correct_key_proof,
        };
        let decom1 = KeyGenDecommitMessage1 {
            blind_factor,
            y_i: self.y_i.clone(),
        };
        (bcm1, decom1)
    }

    #[allow(clippy::type_complexity)]
    pub fn phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
        &self,
        params: &Parameters,
        decom_vec: &[KeyGenDecommitMessage1],
        bc1_vec: &[KeyGenBroadcastMessage1],
    ) -> Result<(VerifiableSS<Secp256k1>, Vec<Scalar<Secp256k1>>, u16), Error> {
        // test length:
        assert_eq!(decom_vec.len(), usize::from(params.share_count));
        assert_eq!(bc1_vec.len(), usize::from(params.share_count));
        // test paillier correct key and test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len()).all(|i| {
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(decom_vec[i].y_i.to_bytes(true).as_ref()),
                &decom_vec[i].blind_factor,
            ) == bc1_vec[i].com
                && bc1_vec[i]
                    .correct_key_proof
                    .verify(&bc1_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                    .is_ok()
        });

        let (vss_scheme, secret_shares) =
            VerifiableSS::share(params.threshold, params.share_count, &self.u_i);
        if correct_key_correct_decom_all {
            Ok((vss_scheme, secret_shares.to_vec(), self.party_index))
        } else {
            Err(InvalidKey)
        }
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: &Parameters,
        y_vec: &[Point<Secp256k1>],
        secret_shares_vec: &[Scalar<Secp256k1>],
        vss_scheme_vec: &[VerifiableSS<Secp256k1>],
        index: u16,
    ) -> Result<(SharedKeys, DLogProof<Secp256k1, Sha256>), Error> {
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(secret_shares_vec.len(), usize::from(params.share_count));
        assert_eq!(vss_scheme_vec.len(), usize::from(params.share_count));

        let correct_ss_verify = (0..y_vec.len()).all(|i| {
            vss_scheme_vec[i]
                .validate_share(&secret_shares_vec[i], index)
                .is_ok()
                && vss_scheme_vec[i].commitments[0] == y_vec[i]
        });

        if correct_ss_verify {
            let y: Point<Secp256k1> = y_vec.iter().sum();
            let x_i: Scalar<Secp256k1> = secret_shares_vec.iter().sum();
            let dlog_proof = DLogProof::prove(&x_i);
            Ok((SharedKeys { y, x_i }, dlog_proof))
        } else {
            Err(InvalidSS)
        }
    }

    pub fn get_commitments_to_xi(
        vss_scheme_vec: &[VerifiableSS<Secp256k1>],
    ) -> Vec<Point<Secp256k1>> {
        let len = vss_scheme_vec.len();
        (1..=u16::try_from(len).unwrap())
            .map(|i| {
                (0..len)
                    .map(|j| vss_scheme_vec[j].get_point_commitment(i))
                    .sum()
            })
            .collect::<Vec<Point<Secp256k1>>>()
    }

    pub fn update_commitments_to_xi(
        comm: &Point<Secp256k1>,
        vss_scheme: &VerifiableSS<Secp256k1>,
        index: u16,
        s: &[u16],
    ) -> Point<Secp256k1> {
        let li =
            VerifiableSS::<Secp256k1>::map_share_to_new_params(&vss_scheme.parameters, index, s);
        comm * &li
    }

    pub fn verify_dlog_proofs(
        params: &Parameters,
        dlog_proofs_vec: &[DLogProof<Secp256k1, Sha256>],
        y_vec: &[Point<Secp256k1>],
    ) -> Result<(), Error> {
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(dlog_proofs_vec.len(), usize::from(params.share_count));

        let xi_dlog_verify =
            (0..y_vec.len()).all(|i| DLogProof::verify(&dlog_proofs_vec[i]).is_ok());

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

    pub fn y_i(&self) -> Point<Secp256k1> {
        Point::generator() * &self.u_i
    }

    pub fn decrypt(&self, ciphertext: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.dk, &RawCiphertext::from(ciphertext))
    }

    pub fn refresh_private_key(&self, factor: &Scalar<Secp256k1>, index: u16) -> Keys {
        let u: Scalar<Secp256k1> = &self.u_i + factor;
        let y = Point::generator() * &u;
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
    pub fn refresh_private_key_safe_prime(&self, factor: &Scalar<Secp256k1>, index: u16) -> Keys {
        let u: Scalar<Secp256k1> = &self.u_i + factor;
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index,
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
    pub fn create(
        private: &PartyPrivate,
        vss_scheme: &VerifiableSS<Secp256k1>,
        index: u16,
        s: &[u16],
    ) -> Self {
        let li =
            VerifiableSS::<Secp256k1>::map_share_to_new_params(&vss_scheme.parameters, index, s);
        let w_i = li * &private.x_i;
        let g = Point::generator();
        let g_w_i = g * &w_i;
        let gamma_i = Scalar::<Secp256k1>::random();
        let g_gamma_i = g * &gamma_i;

        Self {
            w_i,
            g_w_i,
            k_i: Scalar::<Secp256k1>::random(),
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
        assert_eq!(alpha_vec.len(), beta_vec.len());
        let ki_gamma_i = &self.k_i * &self.gamma_i;
        ki_gamma_i + alpha_vec.iter().chain(beta_vec).sum::<Scalar<Secp256k1>>()
    }

    pub fn phase2_sigma_i(
        &self,
        miu_vec: &[Scalar<Secp256k1>],
        ni_vec: &[Scalar<Secp256k1>],
    ) -> Scalar<Secp256k1> {
        assert_eq!(miu_vec.len(), ni_vec.len());
        let ki_w_i = &self.k_i * &self.w_i;
        ki_w_i + miu_vec.iter().chain(ni_vec).sum::<Scalar<Secp256k1>>()
    }

    pub fn phase3_reconstruct_delta(delta_vec: &[Scalar<Secp256k1>]) -> Scalar<Secp256k1> {
        delta_vec
            .iter()
            .sum::<Scalar<Secp256k1>>()
            .invert()
            .expect("sum of deltas is zero")
    }

    pub fn phase4(
        delta_inv: &Scalar<Secp256k1>,
        b_proof_vec: &[&DLogProof<Secp256k1, Sha256>],
        phase1_decommit_vec: Vec<SignDecommitPhase1>,
        bc1_vec: &[SignBroadcastPhase1],
    ) -> Result<Point<Secp256k1>, Error> {
        // note: b_proof_vec is populated using the results
        //from the MtAwc, which is handling the proof of knowledge verification of gamma_i such that
        // Gamme_i = gamma_i * G in the verify_proofs_get_alpha()
        let test_b_vec_and_com = (0..b_proof_vec.len()).all(|i| {
            b_proof_vec[i].pk == phase1_decommit_vec[i].g_gamma_i
                && HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &BigInt::from_bytes(phase1_decommit_vec[i].g_gamma_i.to_bytes(true).as_ref()),
                    &phase1_decommit_vec[i].blind_factor,
                ) == bc1_vec[i].com
        });

        if test_b_vec_and_com {
            Ok({
                let gamma_sum: Point<Secp256k1> = phase1_decommit_vec
                    .iter()
                    .map(|decom| &decom.g_gamma_i)
                    .sum();
                // R
                gamma_sum * delta_inv
            })
        } else {
            Err(InvalidKey)
        }
    }
}

impl LocalSignature {
    pub fn phase5_local_sig(
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
        let s_i = m_fe * k_i + r * sigma_i;
        let l_i = Scalar::<Secp256k1>::random();
        let rho_i = Scalar::<Secp256k1>::random();
        Self {
            l_i,
            rho_i,
            R: R.clone(),
            s_i,
            m: message.clone(),
            y: pubkey.clone(),
        }
    }

    pub fn phase5a_broadcast_5b_zkproof(
        &self,
    ) -> (
        Phase5Com1,
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    ) {
        let blind_factor = BigInt::sample(SECURITY);
        let g = Point::generator();
        let A_i = g * &self.rho_i;
        let l_i_rho_i = &self.l_i * &self.rho_i;
        let B_i = g * l_i_rho_i;
        let V_i = &self.R * &self.s_i + g * &self.l_i;
        let input_hash = Sha256::new()
            .chain_points([&V_i, &A_i, &B_i])
            .result_bigint();
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &input_hash,
            &blind_factor,
        );
        let witness = HomoElGamalWitness {
            r: self.l_i.clone(),
            x: self.s_i.clone(),
        };
        let delta = HomoElGamalStatement {
            G: A_i.clone(),
            H: self.R.clone(),
            Y: g.to_point(),
            D: V_i.clone(),
            E: B_i.clone(),
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
        elgamal_proofs: &[HomoELGamalProof<Secp256k1, Sha256>],
        dlog_proofs_rho: &[DLogProof<Secp256k1, Sha256>],
        v_i: &Point<Secp256k1>,
        R: &Point<Secp256k1>,
    ) -> Result<(Phase5Com2, Phase5DDecom2), Error> {
        assert_eq!(decom_vec.len(), com_vec.len());

        let g = Point::generator();
        let test_com_elgamal = (0..com_vec.len()).all(|i| {
            let delta = HomoElGamalStatement {
                G: decom_vec[i].A_i.clone(),
                H: R.clone(),
                Y: g.to_point(),
                D: decom_vec[i].V_i.clone(),
                E: decom_vec[i].B_i.clone(),
            };

            let input_hash = Sha256::new()
                .chain_points([&decom_vec[i].V_i, &decom_vec[i].A_i, &decom_vec[i].B_i])
                .result_bigint();

            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &input_hash,
                &decom_vec[i].blind_factor,
            ) == com_vec[i].com
                && elgamal_proofs[i].verify(&delta).is_ok()
                && DLogProof::verify(&dlog_proofs_rho[i]).is_ok()
        });

        let v_iter = (0..com_vec.len()).map(|i| &decom_vec[i].V_i);
        let a_iter = (0..com_vec.len()).map(|i| &decom_vec[i].A_i);

        let v = v_i + v_iter.sum::<Point<Secp256k1>>();
        // V = -mG -ry - sum (vi)
        let a: Point<Secp256k1> = a_iter.sum();

        let r = Scalar::<Secp256k1>::from(
            &self
                .R
                .x_coord()
                .ok_or(Error::InvalidSig)?
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let yr = &self.y * r;
        let g = Point::generator();
        let m_fe = Scalar::<Secp256k1>::from(&self.m);
        let gm = g * m_fe;
        let v = v - &gm - &yr;
        let u_i = v * &self.rho_i;
        let t_i = a * &self.l_i;
        let input_hash = Sha256::new().chain_points([&u_i, &t_i]).result_bigint();
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
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
    ) -> Result<Scalar<Secp256k1>, Error> {
        assert_eq!(decom_vec2.len(), decom_vec1.len());
        assert_eq!(decom_vec2.len(), com_vec2.len());

        let test_com = (0..com_vec2.len()).all(|i| {
            let input_hash = Sha256::new()
                .chain_points([&decom_vec2[i].u_i, &decom_vec2[i].t_i])
                .result_bigint();
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &input_hash,
                &decom_vec2[i].blind_factor,
            ) == com_vec2[i].com
        });

        let t_iter = decom_vec2.iter().map(|decom| &decom.t_i);
        let u_iter = decom_vec2.iter().map(|decom| &decom.u_i);
        let b_iter = decom_vec1.iter().map(|decom| &decom.B_i);

        let g = Point::generator();
        let biased_sum_tb = g + t_iter.chain(b_iter).sum::<Point<Secp256k1>>();
        let biased_sum_tb_minus_u = biased_sum_tb - u_iter.sum::<Point<Secp256k1>>();
        if test_com {
            if *g.as_point() == biased_sum_tb_minus_u {
                Ok(self.s_i.clone())
            } else {
                Err(InvalidKey)
            }
        } else {
            Err(InvalidCom)
        }
    }
    pub fn output_signature(&self, s_vec: &[Scalar<Secp256k1>]) -> Result<SignatureRecid, Error> {
        let mut s = &self.s_i + s_vec.iter().sum::<Scalar<Secp256k1>>();
        let s_bn = s.to_bigint();

        let r = Scalar::<Secp256k1>::from(
            &self
                .R
                .x_coord()
                .ok_or(Error::InvalidSig)?
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let ry: BigInt = self
            .R
            .y_coord()
            .ok_or(Error::InvalidSig)?
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
    let b = sig.s.invert().ok_or(Error::InvalidSig)?;
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
                .ok_or(Error::InvalidSig)?
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        )
    {
        Ok(())
    } else {
        Err(InvalidSig)
    }
}
