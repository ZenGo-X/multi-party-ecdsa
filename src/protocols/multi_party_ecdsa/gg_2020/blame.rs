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
use crate::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use crate::utilities::mta::{MessageA, MessageB};
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHProof;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHStatement;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHWitness;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use paillier::traits::EncryptWithChosenRandomness;
use paillier::traits::Open;
use paillier::DecryptionKey;
use paillier::Paillier;
use paillier::{EncryptionKey, Randomness, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalStatePhase5 {
    pub k: Scalar<Secp256k1>,
    pub k_randomness: BigInt,
    pub gamma: Scalar<Secp256k1>,
    pub beta_randomness: Vec<BigInt>,
    pub beta_tag: Vec<BigInt>,
    pub encryption_key: EncryptionKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalStatePhase5 {
    pub k_vec: Vec<Scalar<Secp256k1>>,
    pub k_randomness_vec: Vec<BigInt>,
    pub gamma_vec: Vec<Scalar<Secp256k1>>,
    pub beta_randomness_vec: Vec<Vec<BigInt>>,
    pub beta_tag_vec: Vec<Vec<BigInt>>,
    pub encryption_key_vec: Vec<EncryptionKey>,
    // stuff to check against
    pub delta_vec: Vec<Scalar<Secp256k1>>,
    pub g_gamma_vec: Vec<Point<Secp256k1>>,
    pub m_a_vec: Vec<MessageA>,
    pub m_b_mat: Vec<Vec<MessageB>>,
}

// TODO: check all parties submitted inputs
// TODO: if not - abort gracefully with list of parties that did not produce inputs
impl GlobalStatePhase5 {
    pub fn local_state_to_global_state(
        encryption_key_vec: &[EncryptionKey],
        delta_vec: &[Scalar<Secp256k1>],  //to test against delta_vec
        g_gamma_vec: &[Point<Secp256k1>], // to test against the opened commitment for g_gamma
        m_a_vec: &[MessageA],             // to test against broadcast message A
        m_b_mat: Vec<Vec<MessageB>>,      // to test against broadcast message B
        local_state_vec: &[LocalStatePhase5],
    ) -> Self {
        let len = local_state_vec.len();
        let k_vec = (0..len)
            .map(|i| local_state_vec[i].k.clone())
            .collect::<Vec<Scalar<Secp256k1>>>();
        let k_randomness_vec = (0..len)
            .map(|i| local_state_vec[i].k_randomness.clone())
            .collect::<Vec<BigInt>>();
        let gamma_vec = (0..len)
            .map(|i| local_state_vec[i].gamma.clone())
            .collect::<Vec<Scalar<Secp256k1>>>();
        let beta_randomness_vec = (0..len)
            .map(|i| {
                (0..len - 1)
                    .map(|j| {
                        let ind1 = if j < i { j } else { j + 1 };
                        let ind2 = if j < i { i - 1 } else { i };
                        local_state_vec[ind1].beta_randomness[ind2].clone()
                    })
                    .collect::<Vec<BigInt>>()
            })
            .collect::<Vec<Vec<BigInt>>>();
        let beta_tag_vec = (0..len)
            .map(|i| {
                (0..len - 1)
                    .map(|j| {
                        let ind1 = if j < i { j } else { j + 1 };
                        let ind2 = if j < i { i - 1 } else { i };
                        local_state_vec[ind1].beta_tag[ind2].clone()
                    })
                    .collect::<Vec<BigInt>>()
            })
            .collect::<Vec<Vec<BigInt>>>();

        //  let encryption_key_vec  = (0..len).map(|i| local_state_vec[i].encryption_key.clone() ).collect::<Vec<EncryptionKey>>();
        GlobalStatePhase5 {
            k_vec,
            k_randomness_vec,
            gamma_vec,
            beta_randomness_vec,
            beta_tag_vec,
            encryption_key_vec: encryption_key_vec.to_vec(),
            delta_vec: delta_vec.to_vec(),
            g_gamma_vec: g_gamma_vec.to_vec(),
            m_a_vec: m_a_vec.to_vec(),
            m_b_mat,
        }
    }

    pub fn phase5_blame(&self) -> Result<(), ErrorType> {
        let len = self.delta_vec.len();
        let mut bad_signers_vec = Vec::new();

        // check commitment to g_gamma
        for i in 0..len {
            if self.g_gamma_vec[i] != Point::generator() * &self.gamma_vec[i] {
                bad_signers_vec.push(i)
            }
        }

        let alpha_beta_matrix = (0..len)
            .map(|i| {
                let message_a = MessageA::a_with_predefined_randomness(
                    &self.k_vec[i],
                    &self.encryption_key_vec[i],
                    &self.k_randomness_vec[i],
                    &[],
                );

                // check message a
                if message_a.c != self.m_a_vec[i].c {
                    bad_signers_vec.push(i)
                }

                if bad_signers_vec.is_empty() {
                    (0..len - 1)
                        .map(|j| {
                            let ind = if j < i { j } else { j + 1 };
                            let (message_b, beta) = MessageB::b_with_predefined_randomness(
                                &self.gamma_vec[ind],
                                &self.encryption_key_vec[i],
                                message_a.clone(),
                                &self.beta_randomness_vec[i][j],
                                &self.beta_tag_vec[i][j],
                                &[],
                            )
                            .unwrap();
                            // check message_b
                            if message_b.c != self.m_b_mat[i][j].c {
                                bad_signers_vec.push(ind)
                            }

                            let k_i_gamma_j = &self.k_vec[i] * &self.gamma_vec[ind];
                            let alpha = k_i_gamma_j - &beta;

                            (alpha, beta)
                        })
                        .collect::<Vec<(Scalar<Secp256k1>, Scalar<Secp256k1>)>>()
                } else {
                    vec![]
                }
            })
            .collect::<Vec<Vec<(Scalar<Secp256k1>, Scalar<Secp256k1>)>>>();

        // The matrix we got:
        // [P2, P1, P1, P1  ...]
        // [P3, P3, P2, P2, ...]
        // [P4, P4, P4, P3, ...]
        // [...,            ...]
        // [Pn, Pn, Pn, Pn, ...]
        // We have n columns, one for each party for all the times the party played alice.
        // The Pi's indicate the counter party that played bob

        // we only proceed to check the blame if everyone opened values that are
        // consistent with publicly known commitments and ciphertexts
        if bad_signers_vec.is_empty() {
            //reconstruct delta's
            let delta_vec_reconstruct = (0..len)
                .map(|i| {
                    let k_i_gamma_i = &self.k_vec[i] * &self.gamma_vec[i];

                    let alpha_sum = alpha_beta_matrix[i]
                        .iter()
                        .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + &x.0);
                    let beta_vec = (0..len - 1)
                        .map(|j| {
                            let ind1 = if j < i { j } else { j + 1 };
                            let ind2 = if j < i { i - 1 } else { i };
                            alpha_beta_matrix[ind1][ind2].1.clone()
                        })
                        .collect::<Vec<Scalar<Secp256k1>>>();

                    let beta_sum = beta_vec
                        .iter()
                        .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);

                    k_i_gamma_i + alpha_sum + beta_sum
                })
                .collect::<Vec<Scalar<Secp256k1>>>();

            // compare delta vec to reconstructed delta vec

            #[allow(clippy::needless_range_loop)]
            for i in 0..len {
                if self.delta_vec[i] != delta_vec_reconstruct[i] {
                    bad_signers_vec.push(i)
                }
            }
        }

        bad_signers_vec.sort_unstable();
        bad_signers_vec.dedup();
        let err_type = ErrorType {
            error_type: "phase6_blame".to_string(),
            bad_actors: bad_signers_vec,
        };
        Err(err_type)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalStatePhase6 {
    pub k: Scalar<Secp256k1>,
    pub k_randomness: BigInt,
    pub miu: Vec<BigInt>, // we need the value before reduction
    pub miu_randomness: Vec<BigInt>,
    pub proof_of_eq_dlog: ECDDHProof<Secp256k1, Sha256>,
}

// It is assumed the second message of MtAwc (ciphertext from b to a) is broadcasted in the original protocol
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalStatePhase6 {
    pub k_vec: Vec<Scalar<Secp256k1>>,
    pub k_randomness_vec: Vec<BigInt>,
    pub miu_vec: Vec<Vec<BigInt>>,
    pub miu_randomness_vec: Vec<Vec<BigInt>>,
    pub g_w_vec: Vec<Point<Secp256k1>>,
    pub encryption_key_vec: Vec<EncryptionKey>,
    pub proof_vec: Vec<ECDDHProof<Secp256k1, Sha256>>,
    pub S_vec: Vec<Point<Secp256k1>>,
    pub m_a_vec: Vec<MessageA>,
    pub m_b_mat: Vec<Vec<MessageB>>,
}

impl GlobalStatePhase6 {
    pub fn extract_paillier_randomness(ciphertext: &BigInt, dk: &DecryptionKey) -> BigInt {
        let raw_c = RawCiphertext::from(ciphertext.clone());
        let (_plaintext, randomness) = Paillier::open(dk, raw_c);
        randomness.0
    }

    pub fn ecddh_proof(
        sigma_i: &Scalar<Secp256k1>,
        R: &Point<Secp256k1>,
        S: &Point<Secp256k1>,
    ) -> ECDDHProof<Secp256k1, Sha256> {
        let delta = ECDDHStatement {
            g1: Point::generator().to_point(),
            g2: R.clone(),
            h1: Point::generator() * sigma_i,
            h2: S.clone(),
        };
        let w = ECDDHWitness { x: sigma_i.clone() };
        ECDDHProof::prove(&w, &delta)
    }

    // TODO: check all parties submitted inputs
    // TODO: if not - abort gracefully with list of parties that did not produce inputs
    pub fn local_state_to_global_state(
        encryption_key_vec: &[EncryptionKey],
        S_vec: &[Point<Secp256k1>],
        g_w_vec: &[Point<Secp256k1>],
        m_a_vec: &[MessageA],        // to test against broadcast message A
        m_b_mat: Vec<Vec<MessageB>>, // to test against broadcast message B
        local_state_vec: &[LocalStatePhase6],
    ) -> Self {
        let len = local_state_vec.len();
        let k_vec = (0..len)
            .map(|i| local_state_vec[i].k.clone())
            .collect::<Vec<Scalar<Secp256k1>>>();
        let k_randomness_vec = (0..len)
            .map(|i| local_state_vec[i].k_randomness.clone())
            .collect::<Vec<BigInt>>();
        let proof_vec = (0..len)
            .map(|i| local_state_vec[i].proof_of_eq_dlog.clone())
            .collect::<Vec<ECDDHProof<Secp256k1, Sha256>>>();
        let miu_randomness_vec = (0..len)
            .map(|i| {
                (0..len - 1)
                    .map(|j| local_state_vec[i].miu_randomness[j].clone())
                    .collect::<Vec<BigInt>>()
            })
            .collect::<Vec<Vec<BigInt>>>();
        let miu_vec = (0..len)
            .map(|i| {
                (0..len - 1)
                    .map(|j| local_state_vec[i].miu[j].clone())
                    .collect::<Vec<BigInt>>()
            })
            .collect::<Vec<Vec<BigInt>>>();

        GlobalStatePhase6 {
            k_vec,
            k_randomness_vec,
            miu_vec,
            miu_randomness_vec,
            g_w_vec: g_w_vec.to_vec(),
            encryption_key_vec: encryption_key_vec.to_vec(),
            proof_vec,
            S_vec: S_vec.to_vec(),
            m_a_vec: m_a_vec.to_vec(),
            m_b_mat,
        }
    }

    pub fn phase6_blame(&self, R: &Point<Secp256k1>) -> Result<(), ErrorType> {
        let len = self.k_vec.len();
        let mut bad_signers_vec = Vec::new();

        // check correctness of miu
        for i in 0..len {
            for j in 0..len - 1 {
                if Paillier::encrypt_with_chosen_randomness(
                    &self.encryption_key_vec[i],
                    RawPlaintext::from(self.miu_vec[i][j].clone()),
                    &Randomness::from(self.miu_randomness_vec[i][j].clone()),
                ) != RawCiphertext::from(self.m_b_mat[i][j].c.clone())
                {
                    bad_signers_vec.push(i)
                }
            }
        }

        // check correctness of k
        for i in 0..len {
            if MessageA::a_with_predefined_randomness(
                &self.k_vec[i],
                &self.encryption_key_vec[i],
                &self.k_randomness_vec[i],
                &[],
            )
            .c != self.m_a_vec[i].c
            {
                bad_signers_vec.push(i)
            }
        }

        // we only proceed to check the blame if everyone opened values that are
        // consistent with publicly known ciphertexts sent during MtA
        if bad_signers_vec.is_empty() {
            // compute g_ni
            let g_ni_mat = (0..len)
                .map(|i| {
                    (0..len - 1)
                        .map(|j| {
                            let ind = if j < i { j } else { j + 1 };
                            let k_i = &self.k_vec[i];
                            let g_w_j = &self.g_w_vec[ind];
                            let g_w_j_ki = g_w_j * k_i;
                            let miu: Scalar<Secp256k1> =
                                Scalar::<Secp256k1>::from(&self.miu_vec[i][j]);
                            let g_miu = Point::generator() * &miu;
                            g_w_j_ki - &g_miu
                        })
                        .collect::<Vec<Point<Secp256k1>>>()
                })
                .collect::<Vec<Vec<Point<Secp256k1>>>>();

            // compute g_sigma_i

            let mut g_sigma_i_vec = (0..len)
                .map(|i| {
                    let g_wi_ki = &self.g_w_vec[i] * &self.k_vec[i];
                    let sum = self.miu_vec[i].iter().fold(g_wi_ki, |acc, x| {
                        acc + (Point::generator() * &Scalar::<Secp256k1>::from(&*x))
                    });
                    sum
                })
                .collect::<Vec<Point<Secp256k1>>>();

            #[allow(clippy::needless_range_loop)]
            for i in 0..len {
                for j in 0..len - 1 {
                    let ind1 = if j < i { j } else { j + 1 };
                    let ind2 = if j < i { i - 1 } else { i };
                    g_sigma_i_vec[i] = &g_sigma_i_vec[i] + &g_ni_mat[ind1][ind2];
                }
            }

            // check zero knowledge proof
            #[allow(clippy::needless_range_loop)]
            for i in 0..len {
                let statement = ECDDHStatement {
                    g1: Point::generator().to_point(),
                    g2: R.clone(),
                    h1: g_sigma_i_vec[i].clone(),
                    h2: self.S_vec[i].clone(),
                };

                let result = self.proof_vec[i].verify(&statement);
                if result.is_err() {
                    bad_signers_vec.push(i)
                }
            }
        }

        bad_signers_vec.sort_unstable();
        bad_signers_vec.dedup();
        let err_type = ErrorType {
            error_type: "phase6_blame".to_string(),
            bad_actors: bad_signers_vec,
        };
        Err(err_type)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalStatePhase7 {
    pub s_vec: Vec<Scalar<Secp256k1>>,
    pub r: Scalar<Secp256k1>,
    pub R_dash_vec: Vec<Point<Secp256k1>>,
    pub m: BigInt,
    pub R: Point<Secp256k1>,
    pub S_vec: Vec<Point<Secp256k1>>,
}

impl GlobalStatePhase7 {
    pub fn phase7_blame(&self) -> Result<(), ErrorType> {
        let len = self.s_vec.len(); //TODO: check bounds
        let mut bad_signers_vec = Vec::new();

        for i in 0..len {
            let R_si = &self.R * &self.s_vec[i];
            let R_dash_m = &self.R_dash_vec[i] * &Scalar::<Secp256k1>::from(&self.m);
            let Si_r = &self.S_vec[i] * &self.r;
            let right = R_dash_m + Si_r;
            let left = R_si;
            if left != right {
                bad_signers_vec.push(i);
            }
        }

        let err_type = ErrorType {
            error_type: "phase7_blame".to_string(),
            bad_actors: bad_signers_vec,
        };
        Err(err_type)
    }
}
