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

use ::Point;
use ::BigInt;

pub trait CurveConstCodec {
    fn get_base_point() -> Point;
    fn get_q() -> BigInt;
}

/// Secret Key Codec: BigInt <> SecretKey
pub trait SecretKeyCodec<EC> {
    fn new_random(s: &EC) -> Self;
    fn from_big_int(s: &EC, n: &BigInt) -> Self;

    fn to_big_int(&self) -> BigInt;
}

/// Public Key Codec: Point <> PublicKey
pub trait PublicKeyCodec<EC, SK> {
    const KEY_SIZE: usize;
    const HEADER_MARKER: usize;

    fn randomize(&mut self, s : &EC) -> SK;
    fn to_point(&self) -> Point;

    fn from_key_slice(key: &[u8]) -> Point;
    fn to_key(s : &EC, p: &Point) -> Self;
    fn to_key_slice(p: &Point) -> Vec<u8>;
}