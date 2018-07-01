/*
    Multi-party ECSDA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECSDA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/
use ::BigInteger as BigInt;

use super::traits::Commitment;
use super::ring::digest::{Context, SHA256};
use std::borrow::Borrow;

pub struct HashCommitment;

impl Commitment for HashCommitment {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt, blinding_factor: &BigInt) -> BigInt
    {
        let mut digest = Context::new(&SHA256);
        let bytes_message: Vec<u8> = message.into();
        digest.update(&bytes_message);

        let bytes_blinding_factor: Vec<u8> = blinding_factor.into();
        digest.update(&bytes_blinding_factor);

        BigInt::from(digest.finish().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use ::BigInteger as BigInt;
    use super::Commitment;
    use super::HashCommitment;

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_commitment_test() {
        let commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &BigInt::one(), &BigInt::zero());

        println!("{}", commitment);
    }
}