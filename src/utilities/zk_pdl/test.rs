#![allow(non_snake_case)]
use crate::utilities::zk_pdl::{PDLStatement, PDLWitness, Prover, Verifier};
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use paillier::core::Randomness;
use paillier::traits::{EncryptWithChosenRandomness, KeyGeneration};
use paillier::Paillier;
use paillier::RawPlaintext;

#[test]
fn test_zk_pdl() {
    // pre-test:

    let (ek, dk) = Paillier::keypair().keys();
    let randomness = Randomness::sample(&ek);
    let x: FE = ECScalar::new_random();
    let x: FE = ECScalar::from(&x.to_big_int().div_floor(&BigInt::from(3)));

    let Q = GE::generator() * &x;

    let c = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(x.to_big_int().clone()),
        &randomness,
    )
    .0
    .into_owned();
    let statement = PDLStatement {
        ciphertext: c,
        ek,
        Q,
        G: GE::generator(),
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
