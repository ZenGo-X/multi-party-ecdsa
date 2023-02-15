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

pub mod party_i;

#[cfg(test)]
mod test;

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS as VSS;
pub type VerifiableSS<T> = VSS<T, sha2::Sha256>;
