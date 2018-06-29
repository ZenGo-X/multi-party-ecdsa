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
use std::fmt;

/// A simple Point defined by x and y
pub struct Point  {
    pub x: BigInt,
    pub y: BigInt
}

impl PartialEq for Point {
    fn eq(&self, other: &Point) -> bool {
        self.x == other.x && self.y == other.y
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(x: {}, y: {})", self.x, self.y)
    }
}

impl fmt::Debug for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(x: {}, y: {})", self.x, self.y)
    }
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