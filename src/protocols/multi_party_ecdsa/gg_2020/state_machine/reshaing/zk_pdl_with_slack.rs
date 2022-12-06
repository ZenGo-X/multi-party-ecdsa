#![allow(non_snake_case)]

//! We use the proof as given in proof PIi in https://eprint.iacr.org/2016/013.pdf.
//! This proof ws taken from the proof 6.3 (left side ) in https://www.cs.unc.edu/~reiter/papers/2004/IJIS.pdf
//!
//! Statement: (c, pk, Q, G)
//! witness (x, r) such that Q = xG, c = Enc(pk, x, r)
//! note that because of the range proof, the proof has a slack in the range: x in [-q^3, q^3]

use std::marker::PhantomData;

use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::reshaing::error::{
    FsDkrError, FsDkrResult,
};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::Curve;
use curv::elliptic::curves::Point;
use curv::elliptic::curves::Scalar;
use curv::elliptic::curves::Secp256k1;
use curv::BigInt;
use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PDLwSlackStatement<E: Curve = Secp256k1> {
    pub ciphertext: BigInt,
    pub ek: EncryptionKey,
    pub Q: Point<E>,
    pub G: Point<E>,
    pub h1: BigInt,
    pub h2: BigInt,
    pub N_tilde: BigInt,
}
#[derive(Clone)]
pub struct PDLwSlackWitness<E: Curve = Secp256k1> {
    pub x: Scalar<E>,
    pub r: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDLwSlackProof<E: Curve, H: Digest + Clone> {
    z: BigInt,
    u1: Point<E>,
    u2: BigInt,
    u3: BigInt,
    s1: BigInt,
    s2: BigInt,
    s3: BigInt,
    _phantom: PhantomData<H>,
}

impl<E: Curve, H: Digest + Clone> PDLwSlackProof<E, H> {
    pub fn prove(witness: &PDLwSlackWitness<E>, statement: &PDLwSlackStatement<E>) -> Self {
        let q3 = Scalar::<E>::group_order().pow(3);
        let q_N_tilde = Scalar::<E>::group_order() * &statement.N_tilde;
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
        let u1 = statement.G.clone() * Scalar::<E>::from(&alpha);
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

        let e = H::new()
            .chain_bigint(&BigInt::from_bytes(&statement.G.to_bytes(true)))
            .chain_bigint(&BigInt::from_bytes(&statement.Q.to_bytes(true)))
            .chain_bigint(&statement.ciphertext)
            .chain_bigint(&z)
            .chain_bigint(&BigInt::from_bytes(&u1.to_bytes(true)))
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
            _phantom: PhantomData,
        }
    }

    pub fn verify(&self, statement: &PDLwSlackStatement<E>) -> FsDkrResult<()> {
        let e = H::new()
            .chain_bigint(&BigInt::from_bytes(&statement.G.to_bytes(true)))
            .chain_bigint(&BigInt::from_bytes(&statement.Q.to_bytes(true)))
            .chain_bigint(&statement.ciphertext)
            .chain_bigint(&self.z)
            .chain_bigint(&BigInt::from_bytes(&self.u1.to_bytes(true)))
            .chain_bigint(&self.u2)
            .chain_bigint(&self.u3)
            .result_bigint();

        let g_s1 = statement.G.clone() * Scalar::<E>::from(&self.s1);
        let e_fe_neg = Scalar::<E>::from(&(Scalar::<E>::group_order() - &e));
        let y_minus_e = statement.Q.clone() * e_fe_neg;
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
            Err(FsDkrError::PDLwSlackProof {
                is_u1_eq: self.u1 == u1_test,
                is_u2_eq: self.u2 == u2_test,
                is_u3_eq: self.u3 == u3_test,
            })
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
mod test {
    use super::*;
    use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::reshaing::PAILLIER_KEY_SIZE;
    use curv::elliptic::curves::secp256_k1::{Secp256k1Point, Secp256k1Scalar};
    use curv::BigInt;
    use paillier::core::Randomness;
    use paillier::traits::{EncryptWithChosenRandomness, KeyGeneration};
    use paillier::Paillier;
    use paillier::RawPlaintext;
    use sha2::Sha256;
    use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

    #[test]
    fn test_zk_pdl_with_slack() {
        //  N_tilde, h1, h2 generation
        let (ek_tilde, dk_tilde) = Paillier::keypair_with_modulus_size(PAILLIER_KEY_SIZE).keys();
        // note: safe primes should be used:
        // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
        let one = BigInt::one();
        let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
        let h1 = BigInt::sample_below(&phi);
        let S = BigInt::from(2).pow(256 as u32);
        let xhi = BigInt::sample_below(&S);
        let h1_inv = BigInt::mod_inv(&h1, &ek_tilde.n).unwrap();
        let h2 = BigInt::mod_pow(&h1_inv, &xhi, &ek_tilde.n);
        let statement = DLogStatement {
            N: ek_tilde.n.clone(),
            g: h1.clone(),
            ni: h2.clone(),
        };

        let composite_dlog_proof = CompositeDLogProof::prove(&statement, &xhi);

        // generate the scalar secret and Paillier encrypt it
        let (ek, _dk) = Paillier::keypair_with_modulus_size(PAILLIER_KEY_SIZE).keys();
        // note: safe primes should be used here as well:
        // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
        let randomness = Randomness::sample(&ek);
        let x: Scalar<Secp256k1> = Scalar::<Secp256k1>::random();

        let Q = Point::<Secp256k1>::generator().to_point() * &x;

        let c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(x.to_bigint().clone()),
            &randomness,
        )
        .0
        .into_owned();

        // Generate PDL with slack statement, witness and proof
        let pdl_w_slack_statement = PDLwSlackStatement {
            ciphertext: c,
            ek,
            Q,
            G: Point::<Secp256k1>::generator().to_point(),
            h1,
            h2,
            N_tilde: ek_tilde.n,
        };

        let pdl_w_slack_witness = PDLwSlackWitness { x, r: randomness.0 };

        let proof = PDLwSlackProof::<Secp256k1, Sha256>::prove(
            &pdl_w_slack_witness,
            &pdl_w_slack_statement,
        );
        // verify h1,h2, N_tilde
        let setup_result = composite_dlog_proof.verify(&statement);
        assert!(setup_result.is_ok());
        let result = proof.verify(&pdl_w_slack_statement);
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_zk_pdl_with_slack_soundness() {
        //  N_tilde, h1, h2 generation
        let (ek_tilde, dk_tilde) = Paillier::keypair_with_modulus_size(PAILLIER_KEY_SIZE).keys();
        // note: safe primes should be used:
        // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
        let one = BigInt::one();
        let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
        let h1 = BigInt::sample_below(&phi);
        let S = BigInt::from(2).pow(256 as u32);
        let xhi = BigInt::sample_below(&S);
        let h1_inv = BigInt::mod_inv(&h1, &ek_tilde.n).unwrap();
        let h2 = BigInt::mod_pow(&h1_inv, &xhi, &ek_tilde.n);
        let statement = DLogStatement {
            N: ek_tilde.n.clone(),
            g: h1.clone(),
            ni: h2.clone(),
        };

        let composite_dlog_proof = CompositeDLogProof::prove(&statement, &xhi);

        // generate the scalar secret and Paillier encrypt it
        let (ek, _dk) = Paillier::keypair_with_modulus_size(PAILLIER_KEY_SIZE).keys();
        // note: safe primes should be used here as well:
        // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
        let randomness = Randomness::sample(&ek);
        let x: Scalar<Secp256k1> = Scalar::<Secp256k1>::random();

        let Q = Point::<Secp256k1>::generator().to_point() * &x;

        // here we encrypt x + 1 instead of x:
        let c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(x.to_bigint().clone() + BigInt::one()),
            &randomness,
        )
        .0
        .into_owned();

        // Generate PDL with slack statement, witness and proof
        let pdl_w_slack_statement = PDLwSlackStatement {
            ciphertext: c,
            ek,
            Q,
            G: Point::<Secp256k1>::generator().to_point(),
            h1,
            h2,
            N_tilde: ek_tilde.n,
        };

        let pdl_w_slack_witness = PDLwSlackWitness { x, r: randomness.0 };

        let proof = PDLwSlackProof::<Secp256k1, Sha256>::prove(
            &pdl_w_slack_witness,
            &pdl_w_slack_statement,
        );
        // verify h1,h2, N_tilde
        let setup_result = composite_dlog_proof.verify(&statement);
        assert!(setup_result.is_ok());
        let result = proof.verify(&pdl_w_slack_statement);
        assert!(result.is_ok());
    }
}
