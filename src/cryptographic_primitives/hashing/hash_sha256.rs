use ::BigInt;

use super::traits::Hash;
use super::ring::digest::{Context, SHA256};
use std::borrow::Borrow;

pub struct HSha256;

impl Hash for HSha256 {
    fn create_hash(big_ints: Vec<&BigInt>) -> BigInt {
        let mut digest = Context::new(&SHA256);

        for value in big_ints {
            let bytes: Vec<u8> = value.borrow().into();
            digest.update(&bytes);
        }

        BigInt::from(digest.finish().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use ::BigInt;
    use super::Hash;
    use super::HSha256;

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn create_hash_test() {
        HSha256::create_hash(vec![]);

        let result = HSha256::create_hash(vec![&BigInt::one(), &BigInt::zero()]);
        assert!(result > BigInt::zero());
    }
}