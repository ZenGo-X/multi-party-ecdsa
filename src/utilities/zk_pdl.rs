#![allow(non_snake_case)]

use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::{BigInt, FE, GE};
use paillier::Paillier;
use paillier::{Add, Decrypt, Encrypt, Mul};
use paillier::{DecryptionKey, EncryptionKey, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use std::ops::Shl;
use zk_paillier::zkproofs::RangeProofError;
use zk_paillier::zkproofs::RangeProofNi;
// We use the proof as given in protocol 6.1 in https://eprint.iacr.org/2017/552.pdf
// Statement: (c, pk, Q)
// witness (x, r, sk) such that Q = xG, c = Enc(pk, x, r) and Dec(sk, c) = x.
// note that because of the range proof, the proof is sound only for x < q/3
pub struct Statement {
    pub ciphertext: BigInt,
    pub ek: EncryptionKey,
    pub Q: GE,
}

pub struct Witness {
    pub x: FE,
    pub r: BigInt,
    pub dk: DecryptionKey,
}

#[derive(Debug)]
pub struct VerifierState {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
    a: BigInt,
    b: BigInt,
    blindness: BigInt,
    q_tag: GE,
    c_hat: BigInt,
}

#[derive(Debug, Clone)]
pub struct ProverState {
    pub decommit: ProverDecommit,
    pub alpha: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifierFirstMessage {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverFirstMessage {
    pub c_hat: BigInt,
    pub range_proof: RangeProofNi,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifierSecondMessage {
    pub a: BigInt,
    pub b: BigInt,
    pub blindness: BigInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverDecommit {
    pub q_hat: GE,
    pub blindness: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverSecondMessage {
    pub decommit: ProverDecommit,
}

pub struct Prover {}
pub struct Verifier {}

impl Verifier {
    pub fn message1(statement: &Statement) -> (VerifierFirstMessage, VerifierState) {
        let a_fe: FE = ECScalar::new_random();
        let a = a_fe.to_big_int();
        let q = FE::q();
        let q_sq = q.pow(2);
        let b = BigInt::sample_below(&q_sq);
        let b_fe: FE = ECScalar::from(&b);
        let b_enc = Paillier::encrypt(&statement.ek, RawPlaintext::from(b.clone()));
        let ac = Paillier::mul(
            &statement.ek,
            RawCiphertext::from(statement.ciphertext.clone()),
            RawPlaintext::from(a.clone()),
        );
        let c_tag = Paillier::add(&statement.ek, ac, b_enc).0.into_owned();
        let ab_concat = a.clone() + b.clone().shl(a.bit_length());
        let blindness = BigInt::sample_below(&q);
        let c_tag_tag =
            HashCommitment::create_commitment_with_user_defined_randomness(&ab_concat, &blindness);
        let g: GE = ECPoint::generator();
        let q_tag = &statement.Q * &a_fe + g * b_fe;

        (
            VerifierFirstMessage {
                c_tag: c_tag.clone(),
                c_tag_tag: c_tag_tag.clone(),
            },
            VerifierState {
                c_tag,
                c_tag_tag,
                a,
                b,
                blindness,
                q_tag,
                c_hat: BigInt::zero(),
            },
        )
    }

    pub fn message2(
        prover_first_messasge: &ProverFirstMessage,
        statement: &Statement,
        state: &mut VerifierState,
    ) -> Result<VerifierSecondMessage, ()> {
        let decommit_message = VerifierSecondMessage {
            a: state.a.clone(),
            b: state.b.clone(),
            blindness: state.blindness.clone(),
        };
        let range_proof_is_ok =
            verify_range_proof(&statement, &prover_first_messasge.range_proof).is_ok();
        state.c_hat = prover_first_messasge.c_hat.clone();
        if range_proof_is_ok {
            Ok(decommit_message)
        } else {
            Err(())
        }
    }

    pub fn finalize(
        prover_first_message: &ProverFirstMessage,
        prover_second_message: &ProverSecondMessage,
        state: &VerifierState,
    ) -> Result<(), ()> {
        let c_hat_test = HashCommitment::create_commitment_with_user_defined_randomness(
            &prover_second_message
                .decommit
                .q_hat
                .bytes_compressed_to_big_int(),
            &prover_second_message.decommit.blindness,
        );
        if &prover_first_message.c_hat == &c_hat_test
            && &prover_second_message.decommit.q_hat == &state.q_tag
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Prover {
    pub fn message1(
        witness: &Witness,
        statement: &Statement,
        verifier_first_message: &VerifierFirstMessage,
    ) -> (ProverFirstMessage, ProverState) {
        let c_tag = verifier_first_message.c_tag.clone();
        let alpha = Paillier::decrypt(&witness.dk, &RawCiphertext::from(c_tag.clone()));
        let alpha_fe: FE = ECScalar::from(&alpha.0);
        let g: GE = ECPoint::generator();
        let q_hat = g * alpha_fe;
        let blindness = BigInt::sample_below(&FE::q());
        let c_hat = HashCommitment::create_commitment_with_user_defined_randomness(
            &q_hat.bytes_compressed_to_big_int(),
            &blindness,
        );
        // in parallel generate range proof:
        let range_proof = generate_range_proof(statement, witness);
        (
            ProverFirstMessage { c_hat, range_proof },
            ProverState {
                decommit: ProverDecommit { blindness, q_hat },
                alpha: alpha.0.into_owned(),
            },
        )
    }

    pub fn message2(
        verifier_first_message: &VerifierFirstMessage,
        verifier_second_message: &VerifierSecondMessage,
        witness: &Witness,
        state: &ProverState,
    ) -> Result<ProverSecondMessage, ()> {
        let ab_concat = &verifier_second_message.a
            + verifier_second_message
                .b
                .clone()
                .shl(verifier_second_message.a.bit_length()); // b|a (in the paper it is a|b)
        let c_tag_tag_test = HashCommitment::create_commitment_with_user_defined_randomness(
            &ab_concat,
            &verifier_second_message.blindness,
        );
        let ax1 = &verifier_second_message.a * witness.x.to_big_int();
        let alpha_test = ax1 + &verifier_second_message.b;
        if &alpha_test == &state.alpha && verifier_first_message.c_tag_tag == c_tag_tag_test {
            Ok(ProverSecondMessage {
                decommit: state.decommit.clone(),
            })
        } else {
            Err(())
        }
    }
}

fn generate_range_proof(statement: &Statement, witness: &Witness) -> RangeProofNi {
    RangeProofNi::prove(
        &statement.ek,
        &FE::q(),
        &statement.ciphertext,
        &witness.x.to_big_int(),
        &witness.r,
    )
}

fn verify_range_proof(
    statement: &Statement,
    range_proof: &RangeProofNi,
) -> Result<(), RangeProofError> {
    range_proof.verify(&statement.ek, &statement.ciphertext)
}
