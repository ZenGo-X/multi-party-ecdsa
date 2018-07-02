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
use arithmetic::traits::Samplable;

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

    fn create_commitment(
        message: &BigInt, security_bits: &usize) -> (BigInt, BigInt)
    {
        let mut digest = Context::new(&SHA256);
        let bytes_message: Vec<u8> = message.into();
        digest.update(&bytes_message);
        let blinding_factor = &(BigInt::sample(security_bits.clone()));
        let bytes_blinding_factor: Vec<u8> = blinding_factor.into();
        digest.update(&bytes_blinding_factor);

        (BigInt::from(digest.finish().as_ref()), blinding_factor.clone())
    }
}

#[cfg(test)]
mod tests {
    use ::BigInteger as BigInt;
    use super::Commitment;
    use super::HashCommitment;
    use arithmetic::traits::Samplable;


    #[test]
    fn hash_commitment_test() {
        let sec_bits = 256;
        let message = BigInt::sample(sec_bits.clone());
        let (commitment, blind_factor) = HashCommitment::create_commitment(&message, &sec_bits);
        let commitment2 = HashCommitment::create_commitment_with_user_defined_randomness(
            &message, &blind_factor);
        //test commitment length  - works because SHA256 output length the same as sec_bits
        assert_eq!(commitment.bit_length(),sec_bits);
        //test commitment correctness
        assert_eq!(commitment, commitment2);
        // debug:
        //println!("commitment: {:?}", commitment.to_str_radix(16));
        //println!("length: {:?}", commitment.bit_length());
    }

    #[test]
    fn hash_test() {

        let mut digest = super::Context::new(&super::SHA256);
        let message = BigInt::one();
        let commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &message, &BigInt::zero());
        let message2: Vec<u8> = (&message).into();
        digest.update(&message2);
        assert_eq!(commitment, BigInt::from(digest.finish().as_ref()));
    }

}