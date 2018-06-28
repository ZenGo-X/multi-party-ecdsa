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

use super::gmp::mpz::Mpz;
use super::hex;

pub fn to_bytes(mpz: &Mpz) -> Vec<u8> {
    hex::decode(&mpz.to_str_radix(16)).unwrap()
}

pub type BigInteger = Mpz;