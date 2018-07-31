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
pub mod party_one;
pub mod party_two;

mod test;
mod traits;

use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use cryptography_utils::BigInt;
use cryptography_utils::RawPoint;
use cryptography_utils::PK;
use cryptography_utils::SK;

use paillier::*;

//****************** Begin: Party One structs ******************//
#[derive(Debug)]
pub struct PartyOneKeyGenFirstMsg {
    pub public_share: PK,
    secret_share: SK,
    pub pk_commitment: BigInt,
    pk_commitment_blind_factor: BigInt,

    pub zk_pok_commitment: BigInt,
    zk_pok_blind_factor: BigInt,

    d_log_proof: DLogProof,
}

#[derive(Debug)]
pub struct PartyOneKeyGenSecondMsg {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: PK,
    pub d_log_proof: DLogProof,
}

#[derive(Debug)]
pub struct PartyOnePaillierKeyPair {
    pub ek: EncryptionKey,
    dk: DecryptionKey,
    pub encrypted_share: BigInt,
    randomness: BigInt,
}

#[derive(Debug)]
pub struct PartyOneSignature {
    pub s: BigInt,
    pub r: BigInt,
}

//****************** End: Party One structs ******************//

//****************** Begin: Party One RAW structs ******************//

#[derive(Serialize, Deserialize)]
pub struct RawPartyOneKeyGenFirstMsg {
    pub public_share: RawPoint,
    secret_share: String,
    pub pk_commitment: String,
    pk_commitment_blind_factor: String,

    pub zk_pok_commitment: String,
    zk_pok_blind_factor: String,

    d_log_proof: RawDLogProof,
}

#[derive(Serialize, Deserialize)]
pub struct RawPartyOneKeyGenSecondMsg {
    pub pk_commitment_blind_factor: String,
    pub zk_pok_blind_factor: String,
    pub public_share: RawPoint,
    pub d_log_proof: RawDLogProof,
}

// TODO: add remaining struct

//****************** End: Party One RAW structs ******************//

//****************** Begin: Party Two structs ******************//

#[derive(Debug)]
pub struct PartyTwoKeyGenFirstMsg {
    pub d_log_proof: DLogProof,
    pub public_share: PK,
    secret_share: SK,
}

#[derive(Serialize, Deserialize)]
pub struct RawPartyTwoKeyGenFirstMsg {
    pub d_log_proof: RawDLogProof,
    pub public_share: RawPoint,
    secret_share: String,
}

#[derive(Debug)]
pub struct PartyTwoKeyGenSecondMsg {}

#[derive(Debug)]
pub struct PartyTwoPaillierPublic {
    pub ek: EncryptionKey,
    pub encrypted_secret_share: BigInt,
}

#[derive(Debug)]
pub struct PartyTwoPartialSig {
    pub c3: BigInt,
}

//****************** End: Party Two structs ******************//

//****************** Begin: Party Two RAW structs ******************//

// TODO: add remaining struct

//****************** End: Party Two RAW structs ******************//
