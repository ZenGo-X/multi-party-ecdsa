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

use paillier::KeyGeneration;
use paillier::Paillier;
use paillier::{DecryptionKey, EncryptionKey};
use zk_paillier::zkproofs::NICorrectKeyProof;
use Error::{self, InvalidCom, InvalidKey, InvalidSS, InvalidSig};

use curv::arithmetic::traits::*;

use curv::elliptic::curves::traits::*;

use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::BigInt;
use curv::FE;
use curv::GE;

const SECURITY: usize = 256;

#[derive(Serialize, Deserialize)]
pub struct Keys {
    pub u_i: FE,
    pub y_i: GE,
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub party_index: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenBroadcastMessage1 {
    pub e: EncryptionKey,
    pub com: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage1 {
    pub blind_factor: BigInt,
    pub y_i: GE,
}

#[derive(Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}

#[derive(Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: GE,
    pub x_i: FE,
}

pub struct SignKeys {
    pub w_i: FE,
    pub g_w_i: GE,
    pub k_i: FE,
    pub gamma_i: FE,
    pub g_gamma_i: GE,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignBroadcastPhase1 {
    pub com: BigInt,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignDecommitPhase1 {
    pub blind_factor: BigInt,
    pub g_gamma_i: GE,
}

pub struct LocalSignature {
    pub l_i: FE,
    pub rho_i: FE,
    pub R: GE,
    pub s_i: FE,
    pub m: BigInt,
    pub y: GE,
}
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Phase5Com1 {
    pub com: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Phase5Com2 {
    pub com: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Phase5ADecom1 {
    pub V_i: GE,
    pub A_i: GE,
    pub B_i: GE,
    pub blind_factor: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Phase5DDecom2 {
    pub u_i: GE,
    pub t_i: GE,
    pub blind_factor: BigInt,
}

impl Keys {
    pub fn create(index: usize) -> Keys {
        let u: FE = ECScalar::new_random();
        let y = &ECPoint::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();

        Keys {
            u_i: u,
            y_i: y,
            dk,
            ek,
            party_index: index.clone(),
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
            y_i: self.y_i.clone(),
        };
        (bcm1, decom1)
    }

    pub fn phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
        &self,
        params: &Parameters,
        decom_vec: &Vec<KeyGenDecommitMessage1>,
        bc1_vec: &Vec<KeyGenBroadcastMessage1>,
    ) -> Result<(VerifiableSS, Vec<FE>, usize), Error> {
        // test length:
        assert_eq!(decom_vec.len(), params.share_count);
        assert_eq!(bc1_vec.len(), params.share_count);
        // test paillier correct key and test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::create_commitment_with_user_defined_randomness(
                    &decom_vec[i].y_i.bytes_compressed_to_big_int(),
                    &decom_vec[i].blind_factor,
                ) == bc1_vec[i].com
                    && bc1_vec[i].correct_key_proof.verify(&bc1_vec[i].e).is_ok()
            })
            .all(|x| x == true);

        let (vss_scheme, secret_shares) =
            VerifiableSS::share(params.threshold, params.share_count, &self.u_i);
        match correct_key_correct_decom_all {
            true => Ok((vss_scheme, secret_shares, self.party_index.clone())),
            false => Err(InvalidKey),
        }
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: &Parameters,
        y_vec: &Vec<GE>,
        secret_shares_vec: &Vec<FE>,
        vss_scheme_vec: &Vec<VerifiableSS>,
        index: &usize,
    ) -> Result<(SharedKeys, DLogProof), Error> {
        assert_eq!(y_vec.len(), params.share_count);
        assert_eq!(secret_shares_vec.len(), params.share_count);
        assert_eq!(vss_scheme_vec.len(), params.share_count);

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], *index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0].get_element() == y_vec[i].get_element()
            })
            .all(|x| x == true);

        match correct_ss_verify {
            true => {
                let mut y_vec_iter = y_vec.iter();
                let y0 = y_vec_iter.next().unwrap();
                let y = y_vec_iter.fold(y0.clone(), |acc, x| acc + x);
                let x_i = secret_shares_vec.iter().fold(FE::zero(), |acc, x| acc + x);
                let dlog_proof = DLogProof::prove(&x_i);
                Ok((SharedKeys { y, x_i }, dlog_proof))
            }
            false => Err(InvalidSS),
        }
    }

    pub fn get_commitments_to_xi(vss_scheme_vec: &Vec<VerifiableSS>) -> Vec<GE> {
        let len = vss_scheme_vec.len();
        let xi_points_vec = (1..len + 1)
            .map(|i| {
                let xij_points_vec = (0..len)
                    .map(|j| vss_scheme_vec[j].get_point_commitment(i))
                    .collect::<Vec<GE>>();

                let mut xij_points_iter = xij_points_vec.iter();
                let first = xij_points_iter.next().unwrap();

                let tail = xij_points_iter;
                tail.fold(first.clone(), |acc, x| acc + x)
            })
            .collect::<Vec<GE>>();

        xi_points_vec
    }

    pub fn update_commitments_to_xi(
        comm: &GE,
        vss_scheme: &VerifiableSS,
        index: usize,
        s: &Vec<usize>,
    ) -> GE {
        let li = vss_scheme.map_share_to_new_params(index, s);
        comm * &li
    }

    pub fn verify_dlog_proofs(
        params: &Parameters,
        dlog_proofs_vec: &Vec<DLogProof>,
        y_vec: &Vec<GE>,
    ) -> Result<(), Error> {
        assert_eq!(y_vec.len(), params.share_count);
        assert_eq!(dlog_proofs_vec.len(), params.share_count);
        let xi_dlog_verify = (0..y_vec.len())
            .map(|i| DLogProof::verify(&dlog_proofs_vec[i]).is_ok())
            .all(|x| x == true);

        match xi_dlog_verify {
            true => Ok(()),
            false => Err(InvalidKey),
        }
    }
}

impl SignKeys {
    pub fn create(
        shared_keys: &SharedKeys,
        vss_scheme: &VerifiableSS,
        index: usize,
        s: &Vec<usize>,
    ) -> SignKeys {
        let li = vss_scheme.map_share_to_new_params(index, s);
        let w_i = li * &shared_keys.x_i;
        let g: GE = ECPoint::generator();
        let g_w_i = &g * &w_i;
        let gamma_i: FE = ECScalar::new_random();
        let g_gamma_i = &g * &gamma_i;
        SignKeys {
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
        let g_gamma_i = g * &self.gamma_i;
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &g_gamma_i.bytes_compressed_to_big_int(),
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

    pub fn phase2_delta_i(&self, alpha_vec: &Vec<FE>, beta_vec: &Vec<FE>) -> FE {
        let vec_len = alpha_vec.len();
        assert_eq!(alpha_vec.len(), beta_vec.len());
        // assert_eq!(alpha_vec.len(), self.s.len() - 1);
        let ki_gamma_i = self.k_i.mul(&self.gamma_i.get_element());
        let sum = (0..vec_len)
            .map(|i| alpha_vec[i].add(&beta_vec[i].get_element()))
            .fold(ki_gamma_i, |acc, x| acc + x);
        return sum;
    }

    pub fn phase2_sigma_i(&self, miu_vec: &Vec<FE>, ni_vec: &Vec<FE>) -> FE {
        let vec_len = miu_vec.len();
        assert_eq!(miu_vec.len(), ni_vec.len());
        //assert_eq!(miu_vec.len(), self.s.len() - 1);
        let ki_w_i = self.k_i.mul(&self.w_i.get_element());
        let sum = (0..vec_len)
            .map(|i| miu_vec[i].add(&ni_vec[i].get_element()))
            .fold(ki_w_i, |acc, x| acc + x);
        return sum;
    }

    pub fn phase3_reconstruct_delta(delta_vec: &Vec<FE>) -> FE {
        let sum = delta_vec.iter().fold(FE::zero(), |acc, x| acc + x);
        sum.invert()
    }

    pub fn phase4(
        delta_inv: &FE,
        b_proof_vec: &Vec<&DLogProof>,
        phase1_decommit_vec: Vec<SignDecommitPhase1>,
        // blind_vec: &Vec<BigInt>,
        //  g_gamma_i_vec: &Vec<GE>,
        bc1_vec: &Vec<SignBroadcastPhase1>,
    ) -> Result<GE, Error> {
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
            .all(|x| x == true);

        let mut g_gamma_i_iter = phase1_decommit_vec.iter();
        let head = g_gamma_i_iter.next().unwrap();
        let tail = g_gamma_i_iter;
        match test_b_vec_and_com {
            true => Ok({
                let gamma_sum = tail.fold(head.g_gamma_i.clone(), |acc, x| acc + &x.g_gamma_i);
                let R = gamma_sum * delta_inv;
                R
            }),
            false => Err(InvalidKey),
        }
    }
}

impl LocalSignature {
    pub fn phase5_local_sig(
        k_i: &FE,
        message: &BigInt,
        R: &GE,
        sigma_i: &FE,
        pubkey: &GE,
    ) -> LocalSignature {
        let m_fe: FE = ECScalar::from(message);
        let r: FE = ECScalar::from(&R.x_coor().unwrap().mod_floor(&FE::q()));
        let s_i = m_fe * k_i + r * sigma_i;
        let l_i: FE = ECScalar::new_random();
        let rho_i: FE = ECScalar::new_random();
        LocalSignature {
            l_i,
            rho_i,
            R: R.clone(),
            s_i,
            m: message.clone(),
            y: pubkey.clone(),
        }
    }

    pub fn phase5a_broadcast_5b_zkproof(&self) -> (Phase5Com1, Phase5ADecom1, HomoELGamalProof) {
        let blind_factor = BigInt::sample(SECURITY);
        let g: GE = ECPoint::generator();
        let A_i = &g * &self.rho_i;
        let l_i_rho_i = self.l_i.mul(&self.rho_i.get_element());
        let B_i = &g * &l_i_rho_i;
        let V_i = &self.R * &self.s_i + &g * &self.l_i;
        let input_hash = HSha256::create_hash_from_ge(&[&V_i, &A_i, &B_i]).to_big_int();
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
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
            Y: g,
            D: V_i.clone(),
            E: B_i.clone(),
        };
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
        )
    }

    pub fn phase5c(
        &self,
        decom_vec: &Vec<Phase5ADecom1>,
        com_vec: &Vec<Phase5Com1>,
        elgamal_proofs: &Vec<HomoELGamalProof>,
        v_i: &GE,
        R: &GE,
    ) -> Result<(Phase5Com2, Phase5DDecom2), Error> {
        assert_eq!(decom_vec.len(), com_vec.len());

        let g: GE = ECPoint::generator();
        let test_com_elgamal = (0..com_vec.len())
            .map(|i| {
                let delta = HomoElGamalStatement {
                    G: decom_vec[i].A_i.clone(),
                    H: R.clone(),
                    Y: g.clone(),
                    D: decom_vec[i].V_i.clone(),
                    E: decom_vec[i].B_i.clone(),
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
            })
            .all(|x| x == true);

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
        let yr = &self.y * &r;
        let g: GE = ECPoint::generator();
        let m_fe: FE = ECScalar::from(&self.m);
        let gm = &g * &m_fe;
        let v = v.sub_point(&gm.get_element()).sub_point(&yr.get_element());
        let u_i = &v * &self.rho_i;
        let t_i = &a * &self.l_i;
        let input_hash = HSha256::create_hash_from_ge(&[&u_i, &t_i]).to_big_int();
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &input_hash,
            &blind_factor,
        );

        match test_com_elgamal {
            true => Ok({
                (
                    Phase5Com2 { com },
                    Phase5DDecom2 {
                        u_i,
                        t_i,
                        blind_factor,
                    },
                )
            }),
            false => Err(InvalidCom),
        }
    }

    pub fn phase5d(
        &self,
        decom_vec2: &Vec<Phase5DDecom2>,
        com_vec2: &Vec<Phase5Com2>,
        decom_vec1: &Vec<Phase5ADecom1>,
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
            .all(|x| x == true);

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
        let biased_sum_tb = t_vec
            .iter()
            .zip(b_vec)
            .fold(g.clone(), |acc, x| acc + *x.0 + x.1);
        let biased_sum_tb_minus_u = u_vec
            .iter()
            .fold(biased_sum_tb, |acc, x| acc.sub_point(&x.get_element()));
        match test_com {
            true => {
                if g.get_element() == biased_sum_tb_minus_u.get_element() {
                    Ok(self.s_i.clone())
                } else {
                    Err(InvalidKey)
                }
            }
            false => Err(InvalidCom),
        }
    }
    pub fn output_signature(&self, s_vec: &Vec<FE>) -> Result<(FE, FE), Error> {
        let s = s_vec.iter().fold(self.s_i.clone(), |acc, x| acc + x);
        let r: FE = ECScalar::from(&self.R.x_coor().unwrap().mod_floor(&FE::q()));
        let ver = verify(&s, &r, &self.y, &self.m).is_ok();
        match ver {
            true => Ok((s, r)),
            false => Err(InvalidSig),
        }
    }
}

pub fn verify(s: &FE, r: &FE, y: &GE, message: &BigInt) -> Result<(), Error> {
    let b = s.invert();
    let a: FE = ECScalar::from(message);
    let u1 = a * &b;
    let u2 = r.clone() * &b;

    let g: GE = ECPoint::generator();
    let gu1 = &g * &u1;
    let yu2 = y * &u2;
    // can be faster using shamir trick

    ;
    if r.clone() == ECScalar::from(&(gu1 + yu2).x_coor().unwrap().mod_floor(&FE::q())) {
        Ok(())
    } else {
        Err(InvalidSig)
    }
}
