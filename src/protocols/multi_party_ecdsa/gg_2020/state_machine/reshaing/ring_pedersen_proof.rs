#![allow(non_snake_case)]

/*
    Ring Pedersen Proof
    Copyright 2022 by Webb Technologies.

    ring_pedersen_proof.rs is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.
    @license GPL-3.0+ <https://github.com/KZen-networks/zk-paillier/blob/master/LICENSE>
*/

use bitvec::prelude::*;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::Digest;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::Curve;
use curv::BigInt;
use paillier::EncryptionKey;
use paillier::{KeyGeneration, Paillier};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::reshaing::error::{
    FsDkrError, FsDkrResult,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingPedersenStatement<E: Curve, H: Digest + Clone> {
    pub S: BigInt,
    pub T: BigInt,
    pub N: BigInt,
    phi: BigInt,
    pub ek: EncryptionKey,
    phantom: PhantomData<(E, H)>,
}
#[allow(dead_code)]
pub struct RingPedersenWitness<E: Curve, H: Digest + Clone> {
    p: BigInt,
    q: BigInt,
    lambda: BigInt,
    phantom: PhantomData<(E, H)>,
}

impl<E: Curve, H: Digest + Clone> RingPedersenStatement<E, H> {
    pub fn generate() -> (Self, RingPedersenWitness<E, H>) {
        let (ek_tilde, dk_tilde) = Paillier::keypair_with_modulus_size(2048).keys();
        let one = BigInt::one();
        let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
        let r = BigInt::sample_below(&ek_tilde.n);
        let lambda = BigInt::sample_below(&phi);
        let t = BigInt::mod_pow(&r, &BigInt::from(2), &ek_tilde.n);
        let s = BigInt::mod_pow(&t, &lambda, &ek_tilde.n);

        (
            Self {
                S: s,
                T: t,
                N: ek_tilde.clone().n,
                phi,
                ek: ek_tilde,
                phantom: PhantomData,
            },
            RingPedersenWitness {
                p: dk_tilde.p,
                q: dk_tilde.q,
                lambda,
                phantom: PhantomData,
            },
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingPedersenProof<E: Curve, H: Digest + Clone, const M: usize> {
    A: Vec<BigInt>,
    Z: Vec<BigInt>,
    phantom: PhantomData<(E, H)>,
}

// Link to the UC non-interactive threshold ECDSA paper
impl<E: Curve, H: Digest + Clone, const M: usize> RingPedersenProof<E, H, M> {
    pub fn prove(
        witness: &RingPedersenWitness<E, H>,
        statement: &RingPedersenStatement<E, H>,
    ) -> RingPedersenProof<E, H, M> {
        // 1. Sample alphas from 1 -> m from \phi(N)
        let mut a = [(); M].map(|_| BigInt::zero());
        let mut A = [(); M].map(|_| BigInt::zero());
        let mut hash = H::new();
        for i in 0..M {
            // TODO: Consider ensuring we get a unit element of this subgroup
            let a_i = BigInt::sample_below(&statement.phi);
            a[i] = a_i.clone();
            let A_i = BigInt::mod_pow(&statement.T, &a_i, &statement.N);
            A[i] = A_i.clone();
            hash = H::chain_bigint(hash, &A_i);
        }

        let e: BigInt = hash.result_bigint();
        let bitwise_e: BitVec<u8, Lsb0> = BitVec::from_vec(e.to_bytes());

        let mut Z = [(); M].map(|_| BigInt::zero());
        for i in 0..M {
            let e_i = if bitwise_e[i] {
                BigInt::one()
            } else {
                BigInt::zero()
            };
            let z_i = BigInt::mod_add(&a[i], &(e_i * &witness.lambda), &statement.phi);
            Z[i] = z_i;
        }

        Self {
            A: A.to_vec(),
            Z: Z.to_vec(),
            phantom: PhantomData,
        }
    }

    pub fn verify(
        proof: &RingPedersenProof<E, H, M>,
        statement: &RingPedersenStatement<E, H>,
    ) -> FsDkrResult<()> {
        let mut hash = H::new();
        for i in 0..M {
            hash = H::chain_bigint(hash, &proof.A[i]);
        }

        let e: BigInt = hash.result_bigint();
        let bitwise_e: BitVec<u8, Lsb0> = BitVec::from_vec(e.to_bytes());

        for i in 0..M {
            let mut e_i = 0;
            if bitwise_e[i] {
                e_i = 1;
            }

            if BigInt::mod_pow(&statement.T, &proof.Z[i], &statement.N)
                == BigInt::mod_mul(
                    &proof.A[i],
                    &BigInt::mod_pow(&statement.S, &BigInt::from(e_i), &statement.N),
                    &statement.N,
                )
            {
                continue;
            } else {
                return Err(FsDkrError::RingPedersenProofError);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::reshaing::M_SECURITY;
    use curv::elliptic::curves::secp256_k1::Secp256k1;
    use sha2::Sha256;
    #[test]
    fn test_ring_pedersen() {
        let (statement, witness) = RingPedersenStatement::<Secp256k1, Sha256>::generate();
        let proof = RingPedersenProof::<Secp256k1, Sha256, M_SECURITY>::prove(&witness, &statement);
        assert!(
            RingPedersenProof::<Secp256k1, Sha256, M_SECURITY>::verify(&proof, &statement).is_ok()
        );
    }
}
