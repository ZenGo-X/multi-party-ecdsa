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

use ::EC;
use ::PK;

use elliptic::curves::traits::*;

use cryptographic_primitives::proofs::dlog_zk_protocol::*;

#[derive(Debug)]
pub struct FirstMsgCommitment {
    d_log_proof : DLogProof
}

impl FirstMsgCommitment {
    pub fn create(ec_context: &EC) -> DLogProof {
        let mut pk = PK::to_key(&ec_context, &EC::get_base_point());
        let sk = pk.randomize(&ec_context);

        DLogProof::prove(&ec_context, &pk, &sk)
    }
}