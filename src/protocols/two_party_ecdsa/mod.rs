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

// Fast Secure Two-Party ECDSA Signing by Yehuda Lindell (https://eprint.iacr.org/2017/552.pdf).

pub mod lindell_2017;

// Two-Party ECDSA from Hash Proof Systems and
//Efficient Instantiations (https://eprint.iacr.org/2019/503.pdf)
#[cfg(feature = "cclst")]
pub mod cclst_2019;
