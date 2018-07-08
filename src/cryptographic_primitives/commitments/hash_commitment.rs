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
use ::BigInt;

use super::traits::Commitment;
use super::ring::digest::{Context, SHA256};
use arithmetic::traits::Samplable;
use super::{SECURITY_BITS};
pub struct HashCommitment;


//TODO:  using the function with BigInt's as input instead of string's makes it impossible to commit to empty message or use empty randomness
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
        message: &BigInt) -> (BigInt, BigInt)
    {
        let mut digest = Context::new(&SHA256);
        let bytes_message: Vec<u8> = message.into();
        digest.update(&bytes_message);

        let blinding_factor = &(BigInt::sample(SECURITY_BITS));
        let bytes_blinding_factor: Vec<u8> = blinding_factor.into();
        digest.update(&bytes_blinding_factor);

        (BigInt::from(digest.finish().as_ref()), blinding_factor.clone())
    }
}

#[cfg(test)]
mod tests {
    use ::BigInt;
    use super::Commitment;
    use super::HashCommitment;
    use arithmetic::traits::Samplable;
    use super::{SECURITY_BITS};

    #[test]
    fn test_bit_length_create_commitment() {
        let hex_len = SECURITY_BITS;
        let mut ctr_commit_len = 0;
        let mut ctr_blind_len = 0;
        let sample_size = 100;
        for _ in 1..sample_size {
            let message = BigInt::sample(SECURITY_BITS);
            let (commitment, blind_factor) = HashCommitment::create_commitment(&message);
            if commitment.to_str_radix(2).len() == hex_len {ctr_commit_len = ctr_commit_len + 1;}
            if blind_factor.to_str_radix(2).len() == hex_len {ctr_blind_len = ctr_blind_len + 1;}
        }
        //test commitment length  - works because SHA256 output length the same as sec_bits
        // we test that the probability distribuition is according to what is expected. ideally = 0.5
        let ctr_commit_len = ctr_commit_len as f32;
        let ctr_blind_len = ctr_blind_len as f32;
        let sample_size = sample_size as f32;
        assert!(ctr_commit_len /sample_size  > 0.3);
        assert!(ctr_blind_len /sample_size  > 0.3);
    }

    #[test]
    fn test_bit_length_create_commitment_with_user_defined_randomness() {
        let hex_len = SECURITY_BITS;
        let mut ctr_commit_len = 0;
        let sample_size = 100;
        for _ in 1..sample_size {
            let message = BigInt::sample(SECURITY_BITS);
            let (_commitment, blind_factor) = HashCommitment::create_commitment(&message);
            let commitment2 = HashCommitment::create_commitment_with_user_defined_randomness(&message, &blind_factor);
            if commitment2.to_str_radix(2).len() == hex_len { ctr_commit_len = ctr_commit_len + 1; }
        }
        let ctr_commit_len = ctr_commit_len as f32;
        let sample_size = sample_size as f32;
        assert!(ctr_commit_len / sample_size > 0.3);
    }

    #[test]
    fn test_random_num_generation_create_commitment_with_user_defined_randomness() {
        let message = BigInt::sample(SECURITY_BITS);
        let (commitment, blind_factor) = HashCommitment::create_commitment(&message);
        let commitment2 = HashCommitment::create_commitment_with_user_defined_randomness(
            &message, &blind_factor);
        assert_eq!(commitment, commitment2);
    }


    #[test]
    fn test_hashing_create_commitment_with_user_defined_randomness() {
        let mut digest = super::Context::new(&super::SHA256);
        let message = BigInt::one();
        let commitment = HashCommitment::create_commitment_with_user_defined_randomness(&message, &BigInt::zero());
        let message2: Vec<u8> = (&message).into();
        digest.update(&message2);
        let bytes_blinding_factor: Vec<u8> = (&BigInt::zero()).into();
        digest.update(&bytes_blinding_factor);
        let hash_result = BigInt::from(digest.finish().as_ref());
        assert_eq!(&commitment, &hash_result);

    }

}