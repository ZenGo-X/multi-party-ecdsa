#![allow(non_snake_case)]

//! This file is a modified version of ING bank's range proofs implementation:
//! https://github.com/ing-bank/threshold-signatures/blob/master/src/algorithms/zkp.rs
//!
//! Zero knowledge range proofs for MtA protocol are implemented here.
//! Formal description can be found in Appendix A of https://eprint.iacr.org/2019/114.pdf
//! There are some deviations from the original specification:
//! 1) In Bob's proofs `gamma` is sampled from `[0;q^2 * N]` and `tau` from `[0;q^3 * N_tilde]`.
//! 2) A non-interactive version is implemented, with challenge `e` computed via Fiat-Shamir.

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;

use paillier::{Add, EncryptionKey, Mul, Randomness, RawCiphertext, RawPlaintext};
use zk_paillier::zkproofs::DLogStatement;

use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use zeroize::Zeroize;

/// Represents the first round of the interactive version of the proof
struct AliceZkpRound1 {
    alpha: BigInt,
    beta: BigInt,
    gamma: BigInt,
    ro: BigInt,
    z: BigInt,
    u: BigInt,
    w: BigInt,
}

/// Zeroize Alice's first round
impl Zeroize for AliceZkpRound1 {
    fn zeroize(&mut self) {
        self.alpha.zeroize();
        self.beta.zeroize();
        self.gamma.zeroize();
        self.ro.zeroize();
        self.z.zeroize();
        self.u.zeroize();
        self.w.zeroize();
    }
}

/// Zeroize Alice's first round on drop as it contains secret values
impl Drop for AliceZkpRound1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl AliceZkpRound1 {
    fn from(
        alice_ek: &EncryptionKey,
        dlog_statement: &DLogStatement,
        a: &BigInt,
        q: &BigInt,
    ) -> Self {
        let h1 = &dlog_statement.g;
        let h2 = &dlog_statement.ni;
        let N_tilde = &dlog_statement.N;
        let alpha = BigInt::sample_below(&q.pow(3));
        let beta = BigInt::from_paillier_key(alice_ek);
        let gamma = BigInt::sample_below(&(q.pow(3) * N_tilde));
        let ro = BigInt::sample_below(&(q * N_tilde));
        let z = (BigInt::mod_pow(h1, &a, N_tilde) * BigInt::mod_pow(h2, &ro, N_tilde)) % N_tilde;
        let u = ((alpha.borrow() * &alice_ek.n + 1)
            * BigInt::mod_pow(&beta, &alice_ek.n, &alice_ek.nn))
            % &alice_ek.nn;
        let w =
            (BigInt::mod_pow(h1, &alpha, N_tilde) * BigInt::mod_pow(h2, &gamma, N_tilde)) % N_tilde;
        Self {
            alpha,
            beta,
            gamma,
            ro,
            z,
            u,
            w,
        }
    }
}

/// Represents the second round of the interactive version of the proof
struct AliceZkpRound2 {
    s: BigInt,
    s1: BigInt,
    s2: BigInt,
}

impl AliceZkpRound2 {
    fn from(
        alice_ek: &EncryptionKey,
        round1: &AliceZkpRound1,
        e: &BigInt,
        a: &BigInt,
        r: &BigInt,
    ) -> Self {
        Self {
            s: (BigInt::mod_pow(r, &e, &alice_ek.n) * round1.beta.borrow()) % &alice_ek.n,
            s1: (e * a) + round1.alpha.borrow(),
            s2: (e * round1.ro.borrow()) + round1.gamma.borrow(),
        }
    }
}

/// Alice's proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliceProof {
    z: BigInt,
    e: BigInt,
    s: BigInt,
    s1: BigInt,
    s2: BigInt,
}

impl AliceProof {
    /// verify Alice's proof using the proof and public keys
    pub fn verify(
        &self,
        cipher: &BigInt,
        alice_ek: &EncryptionKey,
        dlog_statement: &DLogStatement,
    ) -> bool {
        let N = &alice_ek.n;
        let NN = &alice_ek.nn;
        let N_tilde = &dlog_statement.N;
        let h1 = &dlog_statement.g;
        let h2 = &dlog_statement.ni;
        let Gen = alice_ek.n.borrow() + 1;

        if self.s1 > FE::q().pow(3) {
            return false;
        }

        let z_e_inv = BigInt::mod_inv(&BigInt::mod_pow(&self.z, &self.e, N_tilde), N_tilde);
        if z_e_inv.is_none() {
            // z must be invertible, yet the check is done here
            return false;
        }
        let z_e_inv = z_e_inv.unwrap();

        let w = (BigInt::mod_pow(h1, &self.s1, N_tilde)
            * BigInt::mod_pow(h2, &self.s2, N_tilde)
            * z_e_inv)
            % N_tilde;

        let gs1 = (self.s1.borrow() * N + 1) % NN;
        let cipher_e_inv = BigInt::mod_inv(&BigInt::mod_pow(&cipher, &self.e, NN), NN);
        if cipher_e_inv.is_none() {
            return false;
        }
        let cipher_e_inv = cipher_e_inv.unwrap();

        let u = (gs1 * BigInt::mod_pow(&self.s, N, NN) * cipher_e_inv) % NN;

        let e = HSha256::create_hash(&[N, &Gen, cipher, &self.z, &u, &w]);
        if e != self.e {
            return false;
        }

        true
    }
    /// Create the proof using Alice's Paillier private keys and public ZKP setup.
    /// Requires randomness used for encrypting Alice's secret a.
    /// It is assumed that secp256k1 curve is used.
    pub fn generate(
        a: &BigInt,
        cipher: &BigInt,
        alice_ek: &EncryptionKey,
        dlog_statement: &DLogStatement,
        r: &BigInt,
    ) -> Self {
        let round1 = AliceZkpRound1::from(alice_ek, dlog_statement, a, &FE::q());

        let Gen = alice_ek.n.borrow() + 1;
        let e = HSha256::create_hash(&[&alice_ek.n, &Gen, cipher, &round1.z, &round1.u, &round1.w]);

        let round2 = AliceZkpRound2::from(alice_ek, &round1, &e, a, r);

        Self {
            z: round1.z.clone(),
            e,
            s: round2.s,
            s1: round2.s1,
            s2: round2.s2,
        }
    }
}

/// Represents first round of the interactive version of the proof
struct BobZkpRound1 {
    pub alpha: BigInt,
    pub beta: BigInt,
    pub gamma: BigInt,
    pub ro: BigInt,
    pub ro_prim: BigInt,
    pub sigma: BigInt,
    pub tau: BigInt,
    pub z: BigInt,
    pub z_prim: BigInt,
    pub t: BigInt,
    pub w: BigInt,
    pub v: BigInt,
}

/// Zeroize Bob's first round
impl Zeroize for BobZkpRound1 {
    fn zeroize(&mut self) {
        self.alpha.zeroize();
        self.beta.zeroize();
        self.gamma.zeroize();
        self.ro.zeroize();
        self.ro_prim.zeroize();
        self.sigma.zeroize();
        self.tau.zeroize();
        self.z.zeroize();
        self.z_prim.zeroize();
        self.t.zeroize();
        self.w.zeroize();
        self.v.zeroize();
    }
}

/// Zeroize Bob's first round on drop as it contains secret values
impl Drop for BobZkpRound1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl BobZkpRound1 {
    /// `b` - Bob's secret
    /// `beta_prim`  - randomly chosen in `MtA` by Bob
    /// `a_encrypted` - Alice's secret encrypted by Alice
    fn from(
        alice_ek: &EncryptionKey,
        dlog_statement: &DLogStatement,
        b: &FE,
        beta_prim: &BigInt,
        a_encrypted: &BigInt,
        q: &BigInt,
    ) -> Self {
        let h1 = &dlog_statement.g;
        let h2 = &dlog_statement.ni;
        let N_tilde = &dlog_statement.N;
        let b_bn = b.to_big_int();

        let alpha = BigInt::sample_below(&q.pow(3));
        let beta = BigInt::from_paillier_key(alice_ek);
        let gamma = BigInt::sample_below(&(q.pow(2) * &alice_ek.n));
        let ro = BigInt::sample_below(&(q * N_tilde));
        let ro_prim = BigInt::sample_below(&(q.pow(3) * N_tilde));
        let sigma = BigInt::sample_below(&(q * N_tilde));
        let tau = BigInt::sample_below(&(q.pow(3) * N_tilde));
        let z = (BigInt::mod_pow(h1, &b_bn, N_tilde) * BigInt::mod_pow(h2, &ro, N_tilde)) % N_tilde;
        let z_prim = (BigInt::mod_pow(h1, &alpha, N_tilde)
            * BigInt::mod_pow(h2, &ro_prim, N_tilde))
            % N_tilde;
        let t = (BigInt::mod_pow(h1, beta_prim, N_tilde) * BigInt::mod_pow(h2, &sigma, N_tilde))
            % N_tilde;
        let w =
            (BigInt::mod_pow(h1, &gamma, N_tilde) * BigInt::mod_pow(h2, &tau, N_tilde)) % N_tilde;
        let v = (BigInt::mod_pow(a_encrypted, &alpha, &alice_ek.nn)
            * (gamma.borrow() * &alice_ek.n + 1)
            * BigInt::mod_pow(&beta, &alice_ek.n, &alice_ek.nn))
            % &alice_ek.nn;
        Self {
            alpha,
            beta,
            gamma,
            ro,
            ro_prim,
            sigma,
            tau,
            z,
            z_prim,
            t,
            w,
            v,
        }
    }
}

/// represents second round of the interactive version of the proof
struct BobZkpRound2 {
    pub s: BigInt,
    pub s1: BigInt,
    pub s2: BigInt,
    pub t1: BigInt,
    pub t2: BigInt,
}

impl BobZkpRound2 {
    /// `e` - the challenge in interactive ZKP, the hash in non-interactive ZKP
    /// `b` - Bob's secret
    /// `beta_prim` - randomly chosen in `MtA` by Bob
    /// `r` - randomness used by Bob on  Alice's public Paillier key to encrypt `beta_prim` in `MtA`
    fn from(
        alice_ek: &EncryptionKey,
        round1: &BobZkpRound1,
        e: &BigInt,
        b: &FE,
        beta_prim: &BigInt,
        r: &Randomness,
    ) -> Self {
        let b_bn = b.to_big_int();
        Self {
            s: (BigInt::mod_pow(r.0.borrow(), e, &alice_ek.n) * round1.beta.borrow()) % &alice_ek.n,
            s1: (e * b_bn) + round1.alpha.borrow(),
            s2: (e * round1.ro.borrow()) + round1.ro_prim.borrow(),
            t1: (e * beta_prim) + round1.gamma.borrow(),
            t2: (e * round1.sigma.borrow()) + round1.tau.borrow(),
        }
    }
}

/// Additional fields in Bob's proof if MtA is run with check
pub struct BobCheck {
    u: GE,
    X: GE,
}

/// Bob's regular proof
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BobProof {
    t: BigInt,
    z: BigInt,
    e: BigInt,
    s: BigInt,
    s1: BigInt,
    s2: BigInt,
    t1: BigInt,
    t2: BigInt,
}

#[allow(clippy::too_many_arguments)]
impl BobProof {
    pub fn verify(
        &self,
        a_enc: &BigInt,
        mta_avc_out: &BigInt,
        alice_ek: &EncryptionKey,
        dlog_statement: &DLogStatement,
        check: Option<&BobCheck>,
    ) -> bool {
        let N = &alice_ek.n;
        let NN = &alice_ek.nn;
        let N_tilde = &dlog_statement.N;
        let h1 = &dlog_statement.g;
        let h2 = &dlog_statement.ni;

        if self.s1 > FE::q().pow(3) {
            return false;
        }

        let z_e_inv = BigInt::mod_inv(&BigInt::mod_pow(&self.z, &self.e, N_tilde), N_tilde);
        if z_e_inv.is_none() {
            // z must be invertible, yet the check is done here
            return false;
        }
        let z_e_inv = z_e_inv.unwrap();

        let z_prim = (BigInt::mod_pow(h1, &self.s1, N_tilde)
            * BigInt::mod_pow(h2, &self.s2, N_tilde)
            * z_e_inv)
            % N_tilde;

        let mta_e_inv = BigInt::mod_inv(&BigInt::mod_pow(mta_avc_out, &self.e, NN), NN);
        if mta_e_inv.is_none() {
            // mta_avc_out must be invertible, yet the check is done here
            return false;
        }
        let mta_e_inv = mta_e_inv.unwrap();

        let v = (BigInt::mod_pow(a_enc, &self.s1, NN)
            * BigInt::mod_pow(&self.s, N, NN)
            * (self.t1.borrow() * N + 1)
            * mta_e_inv)
            % NN;

        let t_e_inv = BigInt::mod_inv(&BigInt::mod_pow(&self.t, &self.e, N_tilde), N_tilde);
        if t_e_inv.is_none() {
            // t must be invertible, yet the check is done here
            return false;
        }
        let t_e_inv = t_e_inv.unwrap();
        let w = (BigInt::mod_pow(h1, &self.t1, N_tilde)
            * BigInt::mod_pow(h2, &self.t2, N_tilde)
            * t_e_inv)
            % N_tilde;

        let Gen = alice_ek.n.borrow() + 1;
        let mut values_to_hash = vec![
            &alice_ek.n,
            &Gen,
            a_enc,
            mta_avc_out,
            &self.z,
            &z_prim,
            &self.t,
            &v,
            &w,
        ];
        let e = if check.is_some() {
            let X_x_coor = check.unwrap().X.x_coor().unwrap();
            values_to_hash.push(&X_x_coor);
            let X_y_coor = check.unwrap().X.y_coor().unwrap();
            values_to_hash.push(&X_y_coor);
            let u_x_coor = check.unwrap().u.x_coor().unwrap();
            values_to_hash.push(&u_x_coor);
            let u_y_coor = check.unwrap().u.y_coor().unwrap();
            values_to_hash.push(&u_y_coor);
            HSha256::create_hash(&values_to_hash[..])
        } else {
            HSha256::create_hash(&values_to_hash[..])
        };

        if e != self.e {
            return false;
        }

        true
    }

    pub fn generate(
        a_encrypted: &BigInt,
        mta_encrypted: &BigInt,
        b: &FE,
        beta_prim: &BigInt,
        alice_ek: &EncryptionKey,
        dlog_statement: &DLogStatement,
        r: &Randomness,
        check: bool,
    ) -> (BobProof, Option<GE>) {
        let round1 = BobZkpRound1::from(
            alice_ek,
            dlog_statement,
            b,
            beta_prim,
            a_encrypted,
            &FE::q(),
        );

        let Gen = alice_ek.n.borrow() + 1;
        let mut values_to_hash = vec![
            &alice_ek.n,
            &Gen,
            a_encrypted,
            mta_encrypted,
            &round1.z,
            &round1.z_prim,
            &round1.t,
            &round1.v,
            &round1.w,
        ];
        let mut check_u = None;
        let e = if check {
            let (X, u) = {
                let ec_gen: GE = ECPoint::generator();
                let alpha: FE = ECScalar::from(&round1.alpha);
                (ec_gen * b, ec_gen * alpha)
            };
            check_u = Some(u);
            let X_x_coor = X.x_coor().unwrap();
            values_to_hash.push(&X_x_coor);
            let X_y_coor = X.y_coor().unwrap();
            values_to_hash.push(&X_y_coor);
            let u_x_coor = u.x_coor().unwrap();
            values_to_hash.push(&u_x_coor);
            let u_y_coor = u.y_coor().unwrap();
            values_to_hash.push(&u_y_coor);
            HSha256::create_hash(&values_to_hash[..])
        } else {
            HSha256::create_hash(&values_to_hash[..])
        };

        let round2 = BobZkpRound2::from(alice_ek, &round1, &e, b, beta_prim, r);

        (
            BobProof {
                t: round1.t.clone(),
                z: round1.z.clone(),
                e,
                s: round2.s,
                s1: round2.s1,
                s2: round2.s2,
                t1: round2.t1,
                t2: round2.t2,
            },
            check_u,
        )
    }
}

/// Bob's extended proof, adds the knowledge of $`B = g^b \in \mathcal{G}`$
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BobProofExt {
    proof: BobProof,
    u: GE,
}

#[allow(clippy::too_many_arguments)]
impl BobProofExt {
    pub fn verify(
        &self,
        a_enc: &BigInt,
        mta_avc_out: &BigInt,
        alice_ek: &EncryptionKey,
        dlog_statement: &DLogStatement,
        X: &GE,
    ) -> bool {
        // check basic proof first
        if !self.proof.verify(
            a_enc,
            mta_avc_out,
            alice_ek,
            dlog_statement,
            Some(&BobCheck { u: self.u, X: *X }),
        ) {
            return false;
        }

        // fiddle with EC points
        let (x1, x2) = {
            let ec_gen: GE = ECPoint::generator();
            let s1: FE = ECScalar::from(&self.proof.s1);
            let e: FE = ECScalar::from(&self.proof.e);
            (ec_gen * s1, (X * &e) + self.u)
        };

        if x1 != x2 {
            return false;
        }

        true
    }

    fn generate(
        a_encrypted: &BigInt,
        mta_encrypted: &BigInt,
        b: &FE,
        beta_prim: &BigInt,
        alice_ek: &EncryptionKey,
        dlog_statement: &DLogStatement,
        r: &Randomness,
    ) -> BobProofExt {
        // proving a basic proof (with modified hash)
        let (bob_proof, u) = BobProof::generate(
            a_encrypted,
            mta_encrypted,
            b,
            beta_prim,
            alice_ek,
            dlog_statement,
            r,
            true,
        );

        BobProofExt {
            proof: bob_proof,
            u: u.unwrap(),
        }
    }
}

/// sample random value of an element of a multiplicative group
pub trait SampleFromMultiplicativeGroup {
    fn from_modulo(N: &BigInt) -> BigInt;
    fn from_paillier_key(ek: &EncryptionKey) -> BigInt;
}

impl SampleFromMultiplicativeGroup for BigInt {
    fn from_modulo(N: &BigInt) -> BigInt {
        let One = BigInt::one();
        loop {
            let r = Self::sample_below(N);
            if r.gcd(N) == One {
                return r;
            }
        }
    }

    fn from_paillier_key(ek: &EncryptionKey) -> BigInt {
        Self::from_modulo(ek.n.borrow())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use paillier::traits::{Encrypt, EncryptWithChosenRandomness, KeyGeneration};
    use paillier::{DecryptionKey, Paillier};

    pub(crate) fn generate_init() -> (DLogStatement, EncryptionKey, DecryptionKey) {
        let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
        let one = BigInt::one();
        let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
        let h1 = BigInt::sample_below(&ek_tilde.n);
        let (xhi, _) = loop {
            let xhi_ = BigInt::sample_below(&phi);
            match BigInt::mod_inv(&xhi_, &phi) {
                Some(inv) => break (xhi_, inv),
                None => continue,
            }
        };
        let h2 = BigInt::mod_pow(&h1, &xhi, &ek_tilde.n);

        let (ek, dk) = Paillier::keypair().keys();
        let dlog_statement = DLogStatement {
            g: h1,
            ni: h2,
            N: ek_tilde.n,
        };
        (dlog_statement, ek, dk)
    }

    #[test]
    fn alice_zkp() {
        let (dlog_statement, ek, _) = generate_init();

        // Alice's secret value
        let a = FE::new_random().to_big_int();
        let r = BigInt::from_paillier_key(&ek);
        let cipher = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(a.clone()),
            &Randomness::from(&r),
        )
        .0
        .clone()
        .into_owned();

        let alice_proof = AliceProof::generate(&a, &cipher, &ek, &dlog_statement, &r);

        assert!(alice_proof.verify(&cipher, &ek, &dlog_statement));
    }

    #[test]
    fn bob_zkp() {
        let (dlog_statement, ek, _) = generate_init();

        (0..5).for_each(|_| {
            let alice_public_key = &ek;

            // run MtA protocol with different inputs
            (0..5).for_each(|_| {
                // Simulate Alice
                let a = FE::new_random().to_big_int();
                let encrypted_a = Paillier::encrypt(alice_public_key, RawPlaintext::from(a))
                    .0
                    .clone()
                    .into_owned();

                // Bob follows MtA
                let b = FE::new_random();
                // E(a) * b
                let b_times_enc_a = Paillier::mul(
                    alice_public_key,
                    RawCiphertext::from(encrypted_a.clone()),
                    RawPlaintext::from(&b.to_big_int()),
                );
                let beta_prim = BigInt::sample_below(&alice_public_key.n);
                let r = Randomness::sample(alice_public_key);
                let enc_beta_prim = Paillier::encrypt_with_chosen_randomness(
                    alice_public_key,
                    RawPlaintext::from(&beta_prim),
                    &r,
                );

                let mta_out = Paillier::add(alice_public_key, b_times_enc_a, enc_beta_prim);

                let (bob_proof, _) = BobProof::generate(
                    &encrypted_a,
                    &mta_out.0.clone().into_owned(),
                    &b,
                    &beta_prim,
                    alice_public_key,
                    &dlog_statement,
                    &r,
                    false,
                );
                assert!(bob_proof.verify(
                    &encrypted_a,
                    &mta_out.0.clone().into_owned(),
                    alice_public_key,
                    &dlog_statement,
                    None
                ));

                // Bob follows MtAwc
                let ec_gen: GE = ECPoint::generator();
                let X = ec_gen * b;
                let bob_proof = BobProofExt::generate(
                    &encrypted_a,
                    &mta_out.0.clone().into_owned(),
                    &b,
                    &beta_prim,
                    alice_public_key,
                    &dlog_statement,
                    &r,
                );
                assert!(bob_proof.verify(
                    &encrypted_a,
                    &mta_out.0.clone().into_owned(),
                    alice_public_key,
                    &dlog_statement,
                    &X
                ));
            });
        });
    }
}
