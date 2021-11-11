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

//! We use the proof as given in proof PIi in https://eprint.iacr.org/2016/013.pdf.
//! This proof ws taken from the proof 6.3 (left side ) in https://www.cs.unc.edu/~reiter/papers/2004/IJIS.pdf
//!
//! Statement: (c, pk, Q, G)
//! witness (x, r) such that Q = xG, c = Enc(pk, x, r)
//! note that because of the range proof, the proof has a slack in the range: x in [-q^3, q^3]

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkPdlWithSlackError {
    #[error("zk pdl with slack verification failed")]
    Verify,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PDLwSlackStatement {
    pub ciphertext: BigInt,
    pub ek: EncryptionKey,
    pub Q: Point<Secp256k1>,
    pub G: Point<Secp256k1>,
    pub h1: BigInt,
    pub h2: BigInt,
    pub N_tilde: BigInt,
}
#[derive(Clone)]
pub struct PDLwSlackWitness {
    pub x: Scalar<Secp256k1>,
    pub r: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDLwSlackProof {
    z: BigInt,
    u1: Point<Secp256k1>,
    u2: BigInt,
    u3: BigInt,
    s1: BigInt,
    s2: BigInt,
    s3: BigInt,
}

impl PDLwSlackProof {
    pub fn prove(witness: &PDLwSlackWitness, statement: &PDLwSlackStatement) -> Self {
        let q3 = Scalar::<Secp256k1>::group_order().pow(3);
        let q_N_tilde = Scalar::<Secp256k1>::group_order() * &statement.N_tilde;
        let q3_N_tilde = &q3 * &statement.N_tilde;

        let alpha = BigInt::sample_below(&q3);
        let one = BigInt::one();
        let beta = BigInt::sample_range(&one, &(&statement.ek.n - &one));
        let rho = BigInt::sample_below(&q_N_tilde);
        let gamma = BigInt::sample_below(&q3_N_tilde);

        let z = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &witness.x.to_bigint(),
            &rho,
        );
        let u1 = &statement.G * &Scalar::<Secp256k1>::from(&alpha);
        let u2 = commitment_unknown_order(
            &(&statement.ek.n + BigInt::one()),
            &beta,
            &statement.ek.nn,
            &alpha,
            &statement.ek.n,
        );
        let u3 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &alpha,
            &gamma,
        );

        let e = Sha256::new()
            .chain_bigint(&BigInt::from_bytes(statement.G.to_bytes(true).as_ref()))
            .chain_bigint(&BigInt::from_bytes(statement.Q.to_bytes(true).as_ref()))
            .chain_bigint(&statement.ciphertext)
            .chain_bigint(&z)
            .chain_bigint(&BigInt::from_bytes(u1.to_bytes(true).as_ref()))
            .chain_bigint(&u2)
            .chain_bigint(&u3)
            .result_bigint();

        let s1 = &e * witness.x.to_bigint() + alpha;
        let s2 = commitment_unknown_order(&witness.r, &beta, &statement.ek.n, &e, &BigInt::one());
        let s3 = &e * rho + gamma;

        PDLwSlackProof {
            z,
            u1,
            u2,
            u3,
            s1,
            s2,
            s3,
        }
    }

    pub fn verify(&self, statement: &PDLwSlackStatement) -> Result<(), ZkPdlWithSlackError> {
        let e = Sha256::new()
            .chain_bigint(&BigInt::from_bytes(statement.G.to_bytes(true).as_ref()))
            .chain_bigint(&BigInt::from_bytes(statement.Q.to_bytes(true).as_ref()))
            .chain_bigint(&statement.ciphertext)
            .chain_bigint(&self.z)
            .chain_bigint(&BigInt::from_bytes(self.u1.to_bytes(true).as_ref()))
            .chain_bigint(&self.u2)
            .chain_bigint(&self.u3)
            .result_bigint();

        let g_s1 = statement.G.clone() * &Scalar::<Secp256k1>::from(&self.s1);
        let e_fe_neg: Scalar<Secp256k1> =
            Scalar::<Secp256k1>::from(&(Scalar::<Secp256k1>::group_order() - &e));
        let y_minus_e = &statement.Q * &e_fe_neg;
        let u1_test = g_s1 + y_minus_e;

        let u2_test_tmp = commitment_unknown_order(
            &(&statement.ek.n + BigInt::one()),
            &self.s2,
            &statement.ek.nn,
            &self.s1,
            &statement.ek.n,
        );
        let u2_test = commitment_unknown_order(
            &u2_test_tmp,
            &statement.ciphertext,
            &statement.ek.nn,
            &BigInt::one(),
            &(-&e),
        );

        let u3_test_tmp = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &self.s1,
            &self.s3,
        );
        let u3_test = commitment_unknown_order(
            &u3_test_tmp,
            &self.z,
            &statement.N_tilde,
            &BigInt::one(),
            &(-&e),
        );

        if self.u1 == u1_test && self.u2 == u2_test && self.u3 == u3_test {
            Ok(())
        } else {
            Err(ZkPdlWithSlackError::Verify)
        }
    }
}

pub fn commitment_unknown_order(
    h1: &BigInt,
    h2: &BigInt,
    N_tilde: &BigInt,
    x: &BigInt,
    r: &BigInt,
) -> BigInt {
    let h1_x = BigInt::mod_pow(h1, x, N_tilde);
    let h2_r = {
        if r < &BigInt::zero() {
            let h2_inv = BigInt::mod_inv(h2, N_tilde).unwrap();
            BigInt::mod_pow(&h2_inv, &(-r), N_tilde)
        } else {
            BigInt::mod_pow(h2, r, N_tilde)
        }
    };
    BigInt::mod_mul(&h1_x, &h2_r, N_tilde)
}

#[cfg(test)]
mod test;
