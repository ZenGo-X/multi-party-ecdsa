use crate::utilities::mta::range_proofs::tests::generate_init;
use crate::utilities::mta::{MessageA, MessageB};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};

#[test]
fn test_mta() {
    let alice_input = Scalar::<Secp256k1>::random();
    let (dlog_statement, ek_alice, dk_alice) = generate_init();
    let bob_input = Scalar::<Secp256k1>::random();
    let (m_a, _) = MessageA::a(&alice_input, &ek_alice, &[dlog_statement.clone()]);
    let (m_b, beta, _, _) = MessageB::b(&bob_input, &ek_alice, m_a, &[dlog_statement]).unwrap();
    let alpha = m_b
        .verify_proofs_get_alpha(&dk_alice, &alice_input)
        .expect("wrong dlog or m_b");

    let left = alpha.0 + beta;
    let right = alice_input * bob_input;
    assert_eq!(left, right);
}
