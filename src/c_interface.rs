use paillier::EncryptionKey;
use std::ffi::{CStr,CString};
use serde::ser::Serialize;
use std::os::raw::c_char;
use protocols::two_party_ecdsa::lindell_2017::*;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use cryptography_utils::{BigInt, GE};

#[no_mangle]
pub extern "C" fn p1_keygen1_public_share(msg: *const party_one::KeyGenFirstMsg) -> *mut GE {
    unsafe {
        let z = Box::new((&*msg).public_share.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen1_pk_commitment(msg: *const party_one::KeyGenFirstMsg) -> *mut BigInt {
    unsafe {
        let z = Box::new((&*msg).pk_commitment.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen1_zk_pok_commitment(msg: *const party_one::KeyGenFirstMsg) -> *mut BigInt {
    unsafe {
        let z = Box::new((&*msg).zk_pok_commitment.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn bigint_delete(msg: *mut BigInt) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn ge_delete(msg: *mut GE) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen1_delete(msg : *mut party_one::KeyGenFirstMsg) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen1_new_create_commitments() -> *mut party_one::KeyGenFirstMsg {
    let x = Box::new(party_one::KeyGenFirstMsg::create_commitments());
    Box::into_raw(x)
}

#[no_mangle]
pub extern "C" fn p2_keygen1_delete(msg : *mut party_two::KeyGenFirstMsg) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p2_keygen1_new_create() -> *mut party_two::KeyGenFirstMsg {
    let x = Box::new(party_two::KeyGenFirstMsg::create());
    Box::into_raw(x)
}

#[no_mangle]
pub extern "C" fn d_log_proof_delete(msg: *mut DLogProof) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn d_log_proof_nullable_new_deserialize(msg: *mut c_char) -> *mut DLogProof {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut DLogProof, // TODO: test this
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn d_log_proof_serialize(msg: *const DLogProof) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        //let y = d_log_proof_new_deserialize(x);
        //d_log_proof_delete(y);
        x
    }
}

#[no_mangle]
pub extern "C" fn c_str_delete(msg: *mut c_char) {
    unsafe {
        CString::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p2_keygen1_d_log_proof(msg: *const party_two::KeyGenFirstMsg) -> *mut DLogProof {
    unsafe {
        let z = Box::new((&*msg).d_log_proof.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p2_keygen1_public_share(msg: *const party_two::KeyGenFirstMsg) -> *mut GE {
    unsafe {
        let z = Box::new((&*msg).public_share.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_delete(msg : *mut party_one::KeyGenSecondMsg) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_nullable_new_verify_and_decommit(p1keygen1 : *const party_one::KeyGenFirstMsg, dlogproof : *const DLogProof) -> *mut party_one::KeyGenSecondMsg {
    unsafe {
        let x = party_one::KeyGenSecondMsg::verify_and_decommit(&*p1keygen1, &*dlogproof);
        match x {
            Err(_err) => 0 as *mut party_one::KeyGenSecondMsg,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_pk_commitment_blind_factor(msg: *const party_one::KeyGenSecondMsg) -> *mut BigInt {
    unsafe {
        let z = Box::new((&*msg).pk_commitment_blind_factor.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_zk_pok_blind_factor(msg: *const party_one::KeyGenSecondMsg) -> *mut BigInt {
    unsafe {
        let z = Box::new((&*msg).zk_pok_blind_factor.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_public_share(msg: *const party_one::KeyGenSecondMsg) -> *mut GE {
    unsafe {
        let z = Box::new((&*msg).public_share.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_d_log_proof(msg: *const party_one::KeyGenSecondMsg) -> *mut DLogProof {
    unsafe {
        let x = serde_json::to_string(&*msg).unwrap();
        let y: party_one::KeyGenSecondMsg = serde_json::from_str(&x).unwrap();
        let z = Box::new(y.d_log_proof);
        Box::into_raw(z)
    }
}

fn conv<T: Serialize>(msg: &T) -> *mut c_char {
    CString::new(
        serde_json::to_string(msg)
            .unwrap_or("error".to_string()
        )
    )
    .unwrap() // safe because it doesn't contain \0
    .into_raw()
}

#[no_mangle]
pub extern "C" fn p2_keygen2_nullable_new_verify_commitments_and_dlog_proof(
    // all these are from party_one
    pk_com: *const BigInt,
    zk_pok: *const BigInt,
    zk_pok_blind: *const BigInt,
    public_share: *const GE,
    pk_com_blind_party: *const BigInt,
    d_log_proof: *const DLogProof,
) -> *mut party_two::KeyGenSecondMsg {
    unsafe {
        let x = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &*pk_com,
            &*zk_pok,
            &*zk_pok_blind,
            &*public_share,
            &*pk_com_blind_party,
            &*d_log_proof,
        );
        match x {
            Ok(msg) => {
                let y = Box::new(msg);
                Box::into_raw(y)
            },
            Err(_err) => 0 as *mut party_two::KeyGenSecondMsg
        }
    }
}

#[no_mangle]
pub extern "C" fn p2_keygen2_delete(msg : *mut party_two::KeyGenSecondMsg) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p1_paillier_pair_new_generate_keypair_and_encrypted_share(msg : *const party_one::KeyGenFirstMsg) -> *mut party_one::PaillierKeyPair {
    unsafe {
        let x = party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&*msg);
        let y = Box::new(x);
        Box::into_raw(y)
    }
}

#[no_mangle]
pub extern "C" fn p1_paillier_pair_ek(msg : *const party_one::PaillierKeyPair) -> *mut EncryptionKey {
    unsafe {
        let z = Box::new((&*msg).ek.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_paillier_pair_encrypted_share(msg : *const party_one::PaillierKeyPair) -> *mut BigInt {
    unsafe {
        let z = Box::new((&*msg).encrypted_share.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_paillier_pair_delete(msg : *mut party_one::PaillierKeyPair) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p2_paillier_public_new(ek_ptr : *const EncryptionKey, encrypted_secret_share_ptr : *const BigInt) -> *mut party_two::PaillierPublic {
    unsafe {
        let ek: EncryptionKey = (&*ek_ptr).clone();
        let encrypted_secret_share: BigInt = (&*encrypted_secret_share_ptr).clone();
        let y = party_two::PaillierPublic { ek, encrypted_secret_share };
        let z = Box::new(y);
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p2_paillier_public_delete(msg : *mut party_two::PaillierPublic) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn encryption_key_delete(msg : *mut paillier::EncryptionKey) {
    unsafe {
        Box::from_raw(msg);
    }
}

pub struct ChalVeriPair {
    challenge: paillier::Challenge,
    verification_aid: paillier::VerificationAid,
}

#[no_mangle]
pub extern "C" fn chal_veri_pair_new(msg : *const party_two::PaillierPublic) -> *mut ChalVeriPair {
    unsafe {
        let (challenge, verification_aid) = party_two::PaillierPublic::generate_correct_key_challenge(&*msg);
        let x = ChalVeriPair {
            challenge,
            verification_aid,
        };
        let y = Box::new(x);
        Box::into_raw(y)
    }
}

#[no_mangle]
pub extern "C" fn chal_veri_pair_challenge(msg : *const ChalVeriPair) -> *mut paillier::Challenge {
    // copying with json since Challenge doesn't impl Clone
    unsafe {
        let z = serde_json::to_string(&(&*msg).challenge)
            .unwrap_or("error".to_string());
        match serde_json::from_str(&z) {
            Err(_e) => 0 as *mut paillier::Challenge,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn chal_veri_pair_verification_aid(msg: *const ChalVeriPair) -> *mut paillier::VerificationAid {
    // copying with json since VerificationAid doesn't impl Clone
    unsafe {
        let z = serde_json::to_string(&(&*msg).verification_aid)
            .unwrap_or("error".to_string());
        match serde_json::from_str(&z) {
            Err(_e) => 0 as *mut paillier::VerificationAid,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn chal_veri_pair_delete(msg : *mut ChalVeriPair) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn challenge_delete(msg: *mut paillier::Challenge) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p1_paillier_pair_nullable_generate_proof_correct_key(p1pair: *const party_one::PaillierKeyPair, chal: *const paillier::Challenge) -> *mut paillier::CorrectKeyProof {
    unsafe {
        let x = party_one::PaillierKeyPair::generate_proof_correct_key(&*p1pair, &*chal);
        match x {
            Err(_e) => 0 as *mut paillier::CorrectKeyProof,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn correct_key_proof_delete(msg: *mut paillier::CorrectKeyProof) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p2_paillier_public_verify_correct_key(c_k_p: *const paillier::CorrectKeyProof, veri_aid : *const paillier::VerificationAid) -> bool {
    unsafe {
        match party_two::PaillierPublic::verify_correct_key(&*c_k_p, &*veri_aid) {
            Ok(_res) => true,
            Err(_e) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn verification_aid_delete(msg: *mut paillier::VerificationAid) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn range_tuple_delete(msg: *mut RangeProofTriple) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn encrypted_pairs_delete(msg: *mut paillier::EncryptedPairs) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn proof_delete(msg: *mut paillier::Proof) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn challenge_bits_delete(msg: *mut paillier::ChallengeBits) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn range_tuple_1(msg: *const RangeProofTriple) -> *mut paillier::EncryptedPairs {
    unsafe {
        let z = serde_json::to_string(&(&*msg).encrypted_pairs)
            .unwrap_or("error".to_string());
        match serde_json::from_str(&z) {
            Err(_e) => 0 as *mut paillier::EncryptedPairs,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn range_tuple_2(msg: *const RangeProofTriple) -> *mut paillier::ChallengeBits {
    unsafe {
        let z = serde_json::to_string(&(&*msg).challenge)
            .unwrap_or("error".to_string());
        match serde_json::from_str(&z) {
            Err(_e) => 0 as *mut paillier::ChallengeBits,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn range_tuple_3(msg: *const RangeProofTriple) -> *mut paillier::Proof {
    unsafe {
        let z = serde_json::to_string(&(&*msg).proof)
            .unwrap_or("error".to_string());
        match serde_json::from_str(&z) {
            Err(_e) => 0 as *mut paillier::Proof,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

pub struct RangeProofTriple {
    encrypted_pairs: paillier::EncryptedPairs,
    challenge: paillier::ChallengeBits,
    proof: paillier::Proof,
}

#[no_mangle]
pub extern "C" fn p1_paillier_pair_generate_range_proof(pkp: *const party_one::PaillierKeyPair, msg : *const party_one::KeyGenFirstMsg) -> *mut RangeProofTriple {
    unsafe {
        let (encrypted_pairs, challenge, proof) = party_one::PaillierKeyPair::generate_range_proof(&*pkp, &*msg);
        let x = RangeProofTriple {
            encrypted_pairs, challenge, proof
        };
        let y = Box::new(x);
        Box::into_raw(y)
    }
}

#[no_mangle]
pub extern "C" fn p2_paillier_public_verify_range_proof(p2pub: *const party_two::PaillierPublic, challenge_bits : *const paillier::ChallengeBits, encrypted_pairs: *const paillier::EncryptedPairs, proof: *const paillier::Proof) -> bool {
    unsafe {
        match party_two::PaillierPublic::verify_range_proof(&*p2pub, &*challenge_bits, &*encrypted_pairs, &*proof) {
            Ok(_res) => true,
            Err(_e) => false,
        }
    }
}

// signing
//

#[no_mangle]
pub extern "C" fn party2private_new_set_private_key(msg : *const party_two::KeyGenFirstMsg) -> *mut party_two::Party2Private {
    unsafe {
        let x = party_two::Party2Private::set_private_key(&*msg);
        let y = Box::new(x);
        Box::into_raw(y)
    }
}

#[no_mangle]
pub extern "C" fn party2private_delete(msg: *mut party_two::Party2Private) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn bigint_new_from_int(num: u64) -> *mut BigInt {
    let x = BigInt::from(num);
    let y = Box::new(x);
    Box::into_raw(y)
}

#[no_mangle]
pub extern "C" fn p2partialsig_delete(msg: *mut party_two::PartialSig) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p2partialsig_new_compute(
        ek: *const EncryptionKey,
        encrypted_secret_share: *const BigInt,
        local_share: *const party_two::Party2Private,
        ephemeral_local_share: *const party_two::KeyGenFirstMsg,
        ephemeral_other_public_share: *const GE,
        message: *const BigInt,
    ) -> *mut party_two::PartialSig {
    unsafe {
        let x = party_two::PartialSig::compute(
                &*ek,
                &*encrypted_secret_share,
                &*local_share,
                &*ephemeral_local_share,
                &*ephemeral_other_public_share,
                &*message
            );
        let y = Box::new(x);
        Box::into_raw(y)
    }
}

#[no_mangle]
pub extern "C" fn party1private_delete(msg: *mut party_one::Party1Private) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn party1private_new_set_private_key(
    ec_key: *const party_one::KeyGenFirstMsg,
    paillier_key: *const party_one::PaillierKeyPair
    ) -> *mut party_one::Party1Private {
    unsafe {
        let x = party_one::Party1Private::set_private_key(
                &*ec_key,
                &*paillier_key,
            );
        let y = Box::new(x);
        Box::into_raw(y)
    }
}

#[no_mangle]
pub extern "C" fn p1signature_new_compute(
    party_one_private: *const party_one::Party1Private,
    partial_sig_c3: *const BigInt,
    ephemeral_local_share: *const party_one::KeyGenFirstMsg,
    ephemeral_other_public_share: *const GE,
    ) -> *mut party_one::Signature {
    unsafe {
        let x = party_one::Signature::compute(
                &*party_one_private,
                &*partial_sig_c3,
                &*ephemeral_local_share,
                &*ephemeral_other_public_share,
            );
        let y = Box::new(x);
        Box::into_raw(y)
    }
}

#[no_mangle]
pub extern "C" fn p1signature_delete(msg: *mut party_one::Signature) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p2partialsig_c3(msg: *const party_two::PartialSig) -> *mut BigInt {
    unsafe {
        let z = Box::new((&*msg).c3.clone());
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_compute_pubkey(
    local_share: *const party_one::KeyGenFirstMsg,
    other_share_public_share: *const GE,
) -> *mut GE {
    unsafe {
        let x = party_one::compute_pubkey(&*local_share, &*other_share_public_share);
        let y = Box::new(x);
        Box::into_raw(y)
    }
}

#[no_mangle]
pub extern "C" fn p1_verify(
    signature: *const party_one::Signature,
    pubkey: *const GE,
    message: *const BigInt,
) -> bool {
    unsafe {
        match party_one::verify(&*signature, &*pubkey, &*message) {
            Ok(_res) => true,
            Err(_e) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen1_serialize(msg: *const party_one::KeyGenFirstMsg) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_serialize(msg: *const party_one::KeyGenSecondMsg) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn p2_keygen1_serialize(msg: *const party_two::KeyGenFirstMsg) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn p1_paillier_pair_serialize(msg: *const party_one::PaillierKeyPair) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn p2_paillier_public_serialize(msg: *const party_two::PaillierPublic) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn party2private_serialize(msg: *const party_two::Party2Private) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn challenge_serialize(msg: *const paillier::Challenge) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn verification_aid_serialize(msg: *const paillier::VerificationAid) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn correct_key_proof_serialize(msg: *const paillier::CorrectKeyProof) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn encrypted_pairs_serialize(msg: *const paillier::EncryptedPairs) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn challenge_bits_serialize(msg: *const paillier::ChallengeBits) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn proof_serialize(msg: *const paillier::Proof) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn p2partialsig_serialize(msg: *const party_two::PartialSig) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn p1signature_serialize(msg: *const party_one::Signature) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn ge_serialize(msg: *const GE) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn bigint_serialize(msg: *const BigInt) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn encryption_key_serialize(msg: *const EncryptionKey) -> *mut c_char {
    unsafe {
        let x = conv(&*msg);
        x
    }
}

#[no_mangle]
pub extern "C" fn bigint_new_deserialize(msg: *mut c_char) -> *mut BigInt {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut BigInt,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn ge_new_deserialize(msg: *mut c_char) -> *mut GE {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut GE,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn encryption_key_new_deserialize(msg: *mut c_char) -> *mut EncryptionKey {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut EncryptionKey,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn verification_aid_new_deserialize(msg: *mut c_char) -> *mut paillier::VerificationAid {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut paillier::VerificationAid,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn challenge_new_deserialize(msg: *mut c_char) -> *mut paillier::Challenge {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut paillier::Challenge,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn correct_key_proof_new_deserialize(msg: *mut c_char) -> *mut paillier::CorrectKeyProof {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut paillier::CorrectKeyProof,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn encrypted_pairs_new_deserialize(msg: *mut c_char) -> *mut paillier::EncryptedPairs {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut paillier::EncryptedPairs,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn challenge_bits_new_deserialize(msg: *mut c_char) -> *mut paillier::ChallengeBits {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut paillier::ChallengeBits,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn proof_new_deserialize(msg: *mut c_char) -> *mut paillier::Proof {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut paillier::Proof,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn p2partialsig_new_deserialize(msg: *mut c_char) -> *mut party_two::PartialSig {
    unsafe {
        let x = CStr::from_ptr(msg).to_string_lossy().into_owned();
        match serde_json::from_str(&x) {
            Err(_e) => 0 as *mut party_two::PartialSig,
            Ok(y) => {
                let z = Box::new(y);
                Box::into_raw(z)
            }
        }
    }
}
