use std::ffi::{CStr,CString};
use serde::ser::Serialize;
use std::os::raw::c_char;
use protocols::two_party_ecdsa::lindell_2017::*;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;
use cryptography_utils::{BigInt, GE};

#[no_mangle]
pub extern "C" fn p1_keygen1_public_share(msg: *const party_one::KeyGenFirstMsg) -> *mut GE {
    unsafe {
        let x = serde_json::to_string(&*msg).unwrap();
        let y: party_one::KeyGenFirstMsg = serde_json::from_str(&x).unwrap();
        let z = Box::new(y.public_share);
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen1_pk_commitment(msg: *const party_one::KeyGenFirstMsg) -> *mut BigInt {
    unsafe {
        let x = serde_json::to_string(&*msg).unwrap();
        let y: party_one::KeyGenFirstMsg = serde_json::from_str(&x).unwrap();
        let z = Box::new(y.pk_commitment);
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen1_zk_pok_commitment(msg: *const party_one::KeyGenFirstMsg) -> *mut BigInt {
    unsafe {
        let x = serde_json::to_string(&*msg).unwrap();
        let y: party_one::KeyGenFirstMsg = serde_json::from_str(&x).unwrap();
        let z = Box::new(y.zk_pok_commitment);
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
            Err(e) => 0 as *mut DLogProof, // TODO: test this
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
        let x = serde_json::to_string(&*msg).unwrap();
        let y: party_two::KeyGenFirstMsg = serde_json::from_str(&x).unwrap();
        let z = Box::new(y.d_log_proof);
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p2_keygen1_public_share(msg: *const party_two::KeyGenFirstMsg) -> *mut GE {
    unsafe {
        let x = serde_json::to_string(&*msg).unwrap();
        let y: party_two::KeyGenFirstMsg = serde_json::from_str(&x).unwrap();
        let z = Box::new(y.public_share);
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p2_keygen2_delete(msg : *mut party_two::KeyGenSecondMsg) {
    unsafe {
        Box::from_raw(msg);
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_nullable_new_verify_and_decommit(p1keygen1 : *const party_one::KeyGenFirstMsg, dlogproof : *const DLogProof) -> *mut party_one::KeyGenSecondMsg {
    unsafe {
        let x = party_one::KeyGenSecondMsg::verify_and_decommit(&*p1keygen1, &*dlogproof);
        match x {
            Err(err) => 0 as *mut party_one::KeyGenSecondMsg,
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
        let x = serde_json::to_string(&*msg).unwrap();
        let y: party_one::KeyGenSecondMsg = serde_json::from_str(&x).unwrap();
        let z = Box::new(y.pk_commitment_blind_factor);
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_zk_pok_blind_factor(msg: *const party_one::KeyGenSecondMsg) -> *mut BigInt {
    unsafe {
        let x = serde_json::to_string(&*msg).unwrap();
        let y: party_one::KeyGenSecondMsg = serde_json::from_str(&x).unwrap();
        let z = Box::new(y.zk_pok_blind_factor);
        Box::into_raw(z)
    }
}

#[no_mangle]
pub extern "C" fn p1_keygen2_public_share(msg: *const party_one::KeyGenSecondMsg) -> *mut GE {
    unsafe {
        let x = serde_json::to_string(&*msg).unwrap();
        let y: party_one::KeyGenSecondMsg = serde_json::from_str(&x).unwrap();
        let z = Box::new(y.public_share);
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
