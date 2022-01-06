#![allow(non_snake_case)]
use crate::utilities::zk_pdl_with_slack::*;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use paillier::core::Randomness;
use paillier::traits::{EncryptWithChosenRandomness, KeyGeneration};
use paillier::Paillier;
use paillier::RawPlaintext;
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

#[test]
fn test_zk_pdl_with_slack() {
    //  N_tilde, h1, h2 generation
    let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
    // note: safe primes should be used:
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
    let one = BigInt::one();
    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    let h1 = BigInt::sample_below(&phi);
    let S = BigInt::from(2).pow(256_u32);
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
    let (ek, _dk) = Paillier::keypair().keys();
    // note: safe primes should be used here as well:
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
    let randomness = Randomness::sample(&ek);
    let x = Scalar::<Secp256k1>::random();

    let Q = Point::generator() * &x;

    let c = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(x.to_bigint()),
        &randomness,
    )
    .0
    .into_owned();

    // Generate PDL with slack statement, witness and proof
    let pdl_w_slack_statement = PDLwSlackStatement {
        ciphertext: c,
        ek,
        Q,
        G: Point::generator().to_point(),
        h1,
        h2,
        N_tilde: ek_tilde.n,
    };

    let pdl_w_slack_witness = PDLwSlackWitness { x, r: randomness.0 };

    let proof = PDLwSlackProof::prove(&pdl_w_slack_witness, &pdl_w_slack_statement);
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
    let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
    // note: safe primes should be used:
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
    let one = BigInt::one();
    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    let h1 = BigInt::sample_below(&phi);
    let S = BigInt::from(2).pow(256_u32);
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
    let (ek, _dk) = Paillier::keypair().keys();
    // note: safe primes should be used here as well:
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();
    let randomness = Randomness::sample(&ek);
    let x = Scalar::<Secp256k1>::random();

    let Q = Point::generator() * &x;

    // here we encrypt x + 1 instead of x:
    let c = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(x.to_bigint() + BigInt::one()),
        &randomness,
    )
    .0
    .into_owned();

    // Generate PDL with slack statement, witness and proof
    let pdl_w_slack_statement = PDLwSlackStatement {
        ciphertext: c,
        ek,
        Q,
        G: Point::generator().to_point(),
        h1,
        h2,
        N_tilde: ek_tilde.n,
    };

    let pdl_w_slack_witness = PDLwSlackWitness { x, r: randomness.0 };

    let proof = PDLwSlackProof::prove(&pdl_w_slack_witness, &pdl_w_slack_statement);
    // verify h1,h2, N_tilde
    let setup_result = composite_dlog_proof.verify(&statement);
    assert!(setup_result.is_ok());
    let result = proof.verify(&pdl_w_slack_statement);
    assert!(result.is_ok());
}
