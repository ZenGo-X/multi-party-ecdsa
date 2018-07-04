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

/// A simple Point defined by x and y
#[derive(PartialEq)]
#[derive(Debug)]
pub struct Point  {
    pub x: BigInt,
    pub y: BigInt
}

#[cfg(test)]
mod tests {
    use super::Point;
    use super::BigInt;

    #[test]
    fn equality_test() {
        let p1 = Point { x: BigInt::one(), y: BigInt::zero() };
        let p2 = Point { x: BigInt::one(), y: BigInt::zero()};
        assert_eq!(p1, p2);

        let p3 = Point { x: BigInt::zero(), y: BigInt::one() };
        assert_ne!(p1, p3);
    }
}