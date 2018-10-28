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

use paillier::*;
use Error::{self, InvalidKey, InvalidSS};

use cryptography_utils::arithmetic::traits::*;

use cryptography_utils::elliptic::curves::traits::*;

use cryptography_utils::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use cryptography_utils::cryptographic_primitives::commitments::traits::Commitment;
use cryptography_utils::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
use cryptography_utils::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use cryptography_utils::BigInt;
use cryptography_utils::FE;
use cryptography_utils::GE;

const SECURITY: usize =  256;
pub struct Keys {
    pub u_i: FE,
    pub y_i: GE,
    dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub party_index: usize,
}

pub struct BroadcastMessage1 {
    e: EncryptionKey,
    com: BigInt,
    correct_key_proof: NICorrectKeyProof,
}

#[derive(Debug)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}

pub struct SharedKeys {
    pub y: GE,
    pub x_i: FE,
}

pub struct SignKeys {
    pub s: Vec<usize>,
    pub w_i: FE,
    pub g_w_i : GE,
    pub k_i: FE,
    pub gamma_i: FE,
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

    pub fn phase1_broadcast_phase3_proof_of_correct_key(&self) -> (BroadcastMessage1, BigInt) {
        let blind_factor = BigInt::sample(SECURITY);
        let correct_key_proof = NICorrectKeyProof::proof(&self.dk);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &self.y_i.x_coor(),
            &blind_factor,
        );
        let bcm1 = BroadcastMessage1 {
            e: self.ek.clone(),
            com,
            correct_key_proof,
        };
        (bcm1, blind_factor)
    }

    pub fn phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
        &self,
        params: &Parameters,
        blind_vec: &Vec<BigInt>,
        y_vec: &Vec<GE>,
        bc1_vec: &Vec<BroadcastMessage1>,
    ) -> Result<(VerifiableSS, Vec<FE>, usize), Error> {
        // test length:
        assert_eq!(blind_vec.len(), params.share_count);
        assert_eq!(bc1_vec.len(), params.share_count);
        assert_eq!(y_vec.len(), params.share_count);
        // test paillier correct key and test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::create_commitment_with_user_defined_randomness(
                    &y_vec[i].x_coor(),
                    &blind_vec[i],
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
                    .validate_share(&secret_shares_vec[i], &index)
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

impl SignKeys{

    pub fn create(shared_keys: &SharedKeys, vss_scheme: &VerifiableSS, index: usize, s: &Vec<usize>) -> SignKeys{
        let li = vss_scheme.map_share_to_new_params(&index, s);
        let w_i = li * &shared_keys.x_i;
        let g : GE = ECPoint::generator();
        let g_w_i = g * &w_i;
        SignKeys{
            s: s.clone(),
            w_i,
            g_w_i,
            k_i: ECScalar::new_random(),
            gamma_i: ECScalar::new_random(),
        }
    }

    pub fn phase1_broadcast(&self) -> (BigInt, BigInt){
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            &self.g_w_i.x_coor(),
            &blind_factor,
        );

        (com, blind_factor)
    }
}