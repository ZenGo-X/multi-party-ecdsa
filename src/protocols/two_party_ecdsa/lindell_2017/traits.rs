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
use super::*;
use cryptography_utils::arithmetic::traits::*;
use cryptography_utils::elliptic::curves::traits::*;

impl From<PartyOneKeyGenFirstMsg> for RawPartyOneKeyGenFirstMsg {
    fn from(keygen_first_message: PartyOneKeyGenFirstMsg) -> Self {
        RawPartyOneKeyGenFirstMsg {
            public_share: RawPoint::from(keygen_first_message.public_share.to_point()),
            secret_share: keygen_first_message.secret_share.to_big_int().to_hex(),
            pk_commitment: keygen_first_message.pk_commitment.to_hex(),
            pk_commitment_blind_factor: keygen_first_message.pk_commitment_blind_factor.to_hex(),
            zk_pok_commitment: keygen_first_message.zk_pok_commitment.to_hex(),
            zk_pok_blind_factor: keygen_first_message.zk_pok_blind_factor.to_hex(),
            d_log_proof: RawDLogProof::from(keygen_first_message.d_log_proof),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography_utils::EC;
    use cryptography_utils::PK;
    use cryptography_utils::SK;
    use serde_json;

    #[test]
    fn test_party_one_keygen_serialization() {
        let valid_key: [u8; PK::KEY_SIZE] = [
            4, // header
            // X
            54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220,
            40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, // Y
            57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193,
            86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188,
        ];

        let s = EC::new();

        let d_log_proof = DLogProof {
            pk: PK::from_slice(&s, &valid_key).unwrap(),
            pk_t_rand_commitment: PK::from_slice(&s, &valid_key).unwrap(),
            challenge_response: BigInt::from(11),
        };

        let party_one_first_message = PartyOneKeyGenFirstMsg {
            public_share: PK::from_slice(&s, &valid_key).unwrap(),
            secret_share: SK::from_big_int(&s, &BigInt::from(1)),
            pk_commitment: BigInt::from(2),
            pk_commitment_blind_factor: BigInt::from(3),
            zk_pok_commitment: BigInt::from(4),
            zk_pok_blind_factor: BigInt::from(5),
            d_log_proof: d_log_proof,
        };

        let party_one_raw_first_message = RawPartyOneKeyGenFirstMsg::from(party_one_first_message);

        let res =
            serde_json::to_string(&party_one_raw_first_message).expect("Failed in serialization");

        assert_eq!(
            res,
            "{\"public_share\":\
             {\"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"secret_share\":\"1\",\
             \"pk_commitment\":\"2\",\
             \"pk_commitment_blind_factor\":\"3\",\
             \"zk_pok_commitment\":\"4\",\
             \"zk_pok_blind_factor\":\"5\",\
             \"d_log_proof\":\
             {\"pk\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"pk_t_rand_commitment\":{\
             \"x\":\"363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b3\",\
             \"y\":\"39ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc\"},\
             \"challenge_response\":\"b\"}}"
        );
    }
}
