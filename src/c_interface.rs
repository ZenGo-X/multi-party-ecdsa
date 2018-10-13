use protocols::two_party_ecdsa::lindell_2017::*;
use cryptography_utils::cryptographic_primitives::proofs::dlog_zk_protocol::DLogProof;

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
pub extern "C" fn p2_keygen1_new_create() -> *mut party_two::KeyGenFirstMsg {
    let x = Box::new(party_two::KeyGenFirstMsg::create());
    Box::into_raw(x)
}

#[no_mangle]
pub extern "C" fn p2_keygen1_d_log_proof(msg: *const party_two::KeyGenFirstMsg) -> *mut DLogProof {
    let x = Box::from_raw(msg); // help, how do i make this not delete msg?
    Box::into_raw(x.d_log_proof)
}

