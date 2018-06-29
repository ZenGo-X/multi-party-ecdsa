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

pub mod elliptic;
pub use elliptic::point::Point as Point;

// TODO: When we will have more than one type of elliptic curve, add as features
pub use elliptic::curves::secp256_k1::EC as EC;
pub use elliptic::curves::secp256_k1::SK as SK;
pub use elliptic::curves::secp256_k1::PK as PK;

pub mod arithmetic;
// TODO: When we will have more than one type of big num library, add as features
pub use arithmetic::big_gmp::BigInteger as BigInteger;

pub mod party_1;
pub mod party_2;
