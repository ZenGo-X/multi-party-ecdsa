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

use paillier::*;
use cryptography_utils::BigInt;
use cryptography_utils::FE;
use cryptography_utils::GE;
use cryptography_utils::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};
use cryptography_utils::elliptic::curves::traits::*;
use Error::{self, InvalidKey};

pub struct MessageA<'a>{
    c: RawCiphertext<'a>, // paillier encryption
}

pub struct MessageB<'a>{
    c: RawCiphertext<'a>, // paillier encryption
    b_proof: DLogProof,
    beta_tag_proof: DLogProof,

}

impl <'a>MessageA<'a> {
    pub fn a(a: &FE, alice_ek: &EncryptionKey) -> MessageA<'a>{
        let c_a = Paillier::encrypt(alice_ek, RawPlaintext::from(a.to_big_int()));
        MessageA{c: c_a}
    }
}

impl <'a>MessageB<'a>{
    pub fn b(b: &FE, alice_ek: &EncryptionKey, c_a: MessageA)->(MessageB<'a>,FE){
        let beta_tag_fe : FE = ECScalar::new_random();
        let c_beta_tag =  Paillier::encrypt(alice_ek, RawPlaintext::from(beta_tag_fe.to_big_int()));
        let b_bn = b.to_big_int();
        let b_c_a = Paillier::mul(
            alice_ek,
            c_a.c,
            RawPlaintext::from(b_bn),
        );
        let c_b = Paillier::add(alice_ek, b_c_a, c_beta_tag);
        let beta = FE::zero().sub(&beta_tag_fe.get_element());
        let dlog_proof_b = DLogProof::prove(b);
        let dlog_proof_beta_tag = DLogProof::prove(&beta_tag_fe);

        ( MessageB{
            c: c_b,
            b_proof: dlog_proof_b,
            beta_tag_proof: dlog_proof_beta_tag,
        }
        ,beta)
    }


    pub fn verify_b(&self, dk: &DecryptionKey, a: &FE) -> Result<FE,Error>{
        let alice_share = Paillier::decrypt(dk, &self.c);
        let g : GE = ECPoint::generator();
        let alpha: FE = ECScalar::from(&alice_share.0);
        let g_alpha = g * &alpha;
        let ba_btag = &self.b_proof.pk * a + &self.beta_tag_proof.pk;
        match DLogProof::verify(&self.b_proof).is_ok()
            &&  DLogProof::verify(&self.beta_tag_proof).is_ok()
            && ba_btag.get_element() == g_alpha.get_element(){
            true => Ok(alpha),
            false => Err(InvalidKey),
        }

    }
}