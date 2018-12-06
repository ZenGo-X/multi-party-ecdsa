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

use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::FE;
use curv::GE;
use paillier::*;

use Error::{self, InvalidKey};

#[derive(Clone, PartialEq, Debug)]
pub struct MessageA<'a> {
    pub c: RawCiphertext<'a>, // paillier encryption
}
#[derive(Clone, PartialEq, Debug)]
pub struct MessageB<'a> {
    pub c: RawCiphertext<'a>, // paillier encryption
    pub b_proof: DLogProof,
    pub beta_tag_proof: DLogProof,
}

impl<'a> MessageA<'a> {
    pub fn a(a: &FE, alice_ek: &EncryptionKey) -> MessageA<'a> {
        let c_a = Paillier::encrypt(alice_ek, RawPlaintext::from(a.to_big_int()));
        MessageA { c: c_a }
    }
}

impl<'a> MessageB<'a> {
    pub fn b(b: &FE, alice_ek: &EncryptionKey, c_a: MessageA) -> (MessageB<'a>, FE) {
        let beta_tag = BigInt::sample_below(&alice_ek.n);
        let beta_tag_fe: FE = ECScalar::from(&beta_tag);
        let c_beta_tag = Paillier::encrypt(alice_ek, RawPlaintext::from(beta_tag));

        let b_bn = b.to_big_int();
        let b_c_a = Paillier::mul(alice_ek, c_a.c, RawPlaintext::from(b_bn));
        let c_b = Paillier::add(alice_ek, b_c_a, c_beta_tag);
        let beta = FE::zero().sub(&beta_tag_fe.get_element());
        let dlog_proof_b = DLogProof::prove(b);
        let dlog_proof_beta_tag = DLogProof::prove(&beta_tag_fe);

        (
            MessageB {
                c: c_b,
                b_proof: dlog_proof_b,
                beta_tag_proof: dlog_proof_beta_tag,
            },
            beta,
        )
    }

    pub fn verify_proofs_get_alpha(&self, dk: &DecryptionKey, a: &FE) -> Result<FE, Error> {
        let alice_share = Paillier::decrypt(dk, &self.c);
        let g: GE = ECPoint::generator();
        let alpha: FE = ECScalar::from(&alice_share.0);
        let g_alpha = g * &alpha;
        let ba_btag = &self.b_proof.pk * a + &self.beta_tag_proof.pk;
        match DLogProof::verify(&self.b_proof).is_ok()
            && DLogProof::verify(&self.beta_tag_proof).is_ok()
            && ba_btag.get_element() == g_alpha.get_element()
        {
            true => Ok(alpha),
            false => Err(InvalidKey),
        }
    }

    pub fn verify_b_against_public(public_gb: &GE, mta_gb: &GE) -> bool {
        public_gb.get_element() == mta_gb.get_element()
    }
}
