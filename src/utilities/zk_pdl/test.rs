#![allow(non_snake_case)]

use curv::arithmetic::traits::*;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use paillier::core::Randomness;
use paillier::traits::{EncryptWithChosenRandomness, KeyGeneration};
use paillier::Paillier;
use paillier::RawPlaintext;

use crate::utilities::zk_pdl::{PDLStatement, PDLWitness, Prover, Verifier};

#[test]
fn test_zk_pdl() {
    // pre-test:

    let (ek, dk) = Paillier::keypair().keys();
    let randomness = Randomness::sample(&ek);
    let x = Scalar::<Secp256k1>::random();
    let x: Scalar<Secp256k1> =
        Scalar::<Secp256k1>::from(&x.to_bigint().div_floor(&BigInt::from(3)));

    let Q = Point::generator() * &x;

    let c = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(x.to_bigint()),
        &randomness,
    )
    .0
    .into_owned();
    let statement = PDLStatement {
        ciphertext: c,
        ek,
        Q,
        G: Point::generator().to_point(),
    };
    let witness = PDLWitness {
        x,
        r: randomness.0,
        dk,
    };
    //
    let (verifier_message1, mut verifier_state) = Verifier::message1(&statement);
    let (prover_message1, prover_state) =
        Prover::message1(&witness, &statement, &verifier_message1);
    let verifier_message2 =
        Verifier::message2(&prover_message1, &statement, &mut verifier_state).expect("");
    let prover_message2 = Prover::message2(
        &verifier_message1,
        &verifier_message2,
        &witness,
        &prover_state,
    )
    .expect("");
    let result = Verifier::finalize(&prover_message1, &prover_message2, &verifier_state);
    assert!(result.is_ok());
}
