#![allow(non_snake_case)]
use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::reshaing::error::{
    FsDkrError, FsDkrResult,
};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::DigestExt;
use curv::elliptic::curves::Curve;
use curv::elliptic::curves::Point;
use curv::elliptic::curves::Scalar;
use curv::BigInt;
use paillier::Paillier;
use paillier::{Add, EncryptWithChosenRandomness, Mul, RawCiphertext};
use paillier::{EncryptionKey, Randomness, RawPlaintext};

use curv::arithmetic::{Modulo, Samplable};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;

/// non interactive proof of fairness, taken from <https://hal.inria.fr/inria-00565274/document>

/// Witness: x
///
/// Statement: {c, Y} such that c = g^x * r^N mod N^2  and Y = x*G
///
/// Protocol:
///
/// 1. P picks random values u from Z_n, s from Z_n*
///    and computes e_u = g^u * s^N mod N^2 ,  T = u*G
/// 2. using Fiat-Shamir the parties computes a challenge e
/// 3. P sends z = u + ex , w = s* r^e mod N^2
/// 4. V checks:
///     T  = z*G - e*Y
///     e_u = g^z * w^N * c^{-e} mod N^2
///
/// note: we need u to hide ex : |u| > |ex| + SEC_PARAM, taking u from Z_n works assuming
/// n = 2048, |x| < 256, |e| < 256

/// non interactive proof of fairness, taken from <https://hal.inria.fr/inria-00565274/document>

/// Witness: x
///
/// Statement: {c, Y} such that c = g^x * r^N mod N^2  and Y = x*G
///
/// Protocol:
///
/// 1. P picks random values u from Z_n, s from Z_n*
///    and computes e_u = g^u * s^N mod N^2 ,  T = u*G
/// 2. using Fiat-Shamir the parties computes a challenge e
/// 3. P sends z = u + ex , w = s* r^e mod N^2
/// 4. V checks:
///     T  = z*G - e*Y
///     e_u = g^z * w^N * c^{-e} mod N^2
///
/// note: we need u to hide ex : |u| > |ex| + SEC_PARAM, taking u from Z_n works assuming
/// n = 2048, |x| < 256, |e| < 256

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct FairnessProof<E: Curve> {
    pub e_u: BigInt,
    pub T: Point<E>,
    pub z: BigInt,
    pub w: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct FairnessWitness<E: Curve> {
    pub r: BigInt,
    pub x: Scalar<E>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct FairnessStatement<E: Curve> {
    pub ek: EncryptionKey,
    pub c: BigInt,
    pub Y: Point<E>,
}

impl<E: Curve> FairnessProof<E> {
    pub fn prove(witness: &FairnessWitness<E>, statement: &FairnessStatement<E>) -> Self {
        let u = BigInt::sample_below(&statement.ek.n);
        let s = BigInt::sample_below(&statement.ek.n);
        let e_u = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(u.clone()),
            &Randomness(s.clone()),
        )
        .0
        .into_owned();
        let u_fe = Scalar::from(&u);
        let T = Point::<E>::generator() * u_fe;

        let e = Sha256::new()
            .chain_bigint(&BigInt::from_bytes(T.to_bytes(true).as_ref()))
            .chain_bigint(&e_u)
            .chain_bigint(&statement.c)
            .chain_bigint(&statement.ek.n)
            .chain_bigint(&BigInt::from_bytes(statement.Y.to_bytes(true).as_ref()))
            .result_bigint();

        let z = u + &e * &witness.x.to_bigint();
        let r_x_e = BigInt::mod_pow(&witness.r, &e, &statement.ek.nn);
        let w = BigInt::mod_mul(&r_x_e, &s, &statement.ek.nn);
        FairnessProof { e_u, T, z, w }
    }

    pub fn verify(&self, statement: &FairnessStatement<E>) -> FsDkrResult<()> {
        let e = Sha256::new()
            .chain_bigint(&BigInt::from_bytes(self.T.to_bytes(true).as_ref()))
            .chain_bigint(&self.e_u)
            .chain_bigint(&statement.c)
            .chain_bigint(&statement.ek.n)
            .chain_bigint(&BigInt::from_bytes(statement.Y.to_bytes(true).as_ref()))
            .result_bigint();

        let enc_z_w = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(self.z.clone()),
            &Randomness(self.w.clone()),
        )
        .0
        .into_owned();
        let c_e = Paillier::mul(
            &statement.ek,
            RawCiphertext::from(statement.c.clone()),
            RawPlaintext::from(e.clone()),
        );
        let e_u_add_c_e = Paillier::add(&statement.ek, RawCiphertext::from(self.e_u.clone()), c_e)
            .0
            .into_owned();

        let z_fe = Scalar::from(&self.z);
        let z_G = Point::generator() * z_fe;
        let e_fe = Scalar::from(&e);
        let e_Y = statement.Y.clone() * e_fe;
        let T_add_e_Y = e_Y + self.T.clone();

        match T_add_e_Y == z_G && e_u_add_c_e == enc_z_w {
            true => Ok(()),
            false => Err(FsDkrError::FairnessProof {
                t_add_eq_z_g: T_add_e_Y == z_G,
                e_u_add_eq_z_w: e_u_add_c_e == enc_z_w,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::arithmetic::Samplable;
    use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};

    use curv::BigInt;
    use paillier::{
        EncryptWithChosenRandomness, KeyGeneration, Paillier, Randomness, RawPlaintext,
    };

    #[test]
    fn test_fairness_proof() {
        let (ek, _) = Paillier::keypair().keys();

        let x: Scalar<Secp256k1> = Scalar::random();
        let x_bn = x.to_bigint();
        let r = BigInt::sample_below(&ek.n);

        let c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(x_bn),
            &Randomness(r.clone()),
        )
        .0
        .into_owned();

        let Y = Point::generator().to_owned() * &x;
        let witness = FairnessWitness { x, r };

        let statement = FairnessStatement { ek, c, Y };

        let proof = FairnessProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);

        assert!(verify.is_ok());
    }

    #[test]
    fn test_bad_fairness_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let x: Scalar<Secp256k1> = Scalar::random();
        let x_bn = x.to_bigint();
        let r = BigInt::sample_below(&ek.n);

        let c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(x_bn + BigInt::one()),
            &Randomness(r.clone()),
        )
        .0
        .into_owned();

        let Y = Point::generator().to_owned() * &x;

        let witness = FairnessWitness { x, r };

        let statement = FairnessStatement { ek, c, Y };

        let proof = FairnessProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_err());
    }
}
