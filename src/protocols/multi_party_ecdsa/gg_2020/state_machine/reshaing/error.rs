use thiserror::Error;

pub type FsDkrResult<T> = Result<T, FsDkrError>;

#[derive(Error, Debug, Clone)]
pub enum FsDkrError {
    #[error("Too many malicious parties detected! Threshold {threshold:?}, Number of Refreshed Messages: {refreshed_keys:?}, Malicious parties detected when trying to refresh: malicious_parties:?")]
    PartiesThresholdViolation {
        threshold: u16,
        refreshed_keys: usize,
        // TODO: figure out how to retrieve the malicious parties indexes and add them to the err.
        // malicious_parties: [usize]
    },

    #[error("Shares did not pass verification.")]
    PublicShareValidationError,

    #[error("SizeMismatch error for the refresh message {refresh_message_index:?} - pdl proof length: {pdl_proof_len:?}, Points Commited Length: {points_commited_len:?}, Points Encrypted Length: {points_encrypted_len:?}")]
    SizeMismatchError {
        refresh_message_index: usize,
        pdl_proof_len: usize,
        points_commited_len: usize,
        points_encrypted_len: usize,
    },

    #[error("PDLwSlack proof verification failed, results: u1 == u1_test: {is_u1_eq:?}, u2 == u2_test: {is_u2_eq:?}, u3 == u3_test: {is_u3_eq:?}")]
    PDLwSlackProof {
        is_u1_eq: bool,
        is_u2_eq: bool,
        is_u3_eq: bool,
    },

    #[error("Ring Pedersen Proof Failed")]
    RingPedersenProofError,

    #[error("Range Proof failed for party: {party_index:?}")]
    RangeProof { party_index: usize },

    #[error("The Paillier moduli size of party: {party_index:?} is {moduli_size:?} bits, when it should be 2047-2048 bits")]
    ModuliTooSmall {
        party_index: u16,
        moduli_size: usize,
    },

    #[error("Paillier verification proof failed for party {party_index:?}")]
    PaillierVerificationError { party_index: u16 },

    #[error("A new party did not receive a valid index.")]
    NewPartyUnassignedIndexError,

    #[error("The broadcasted public key is not the same from everyone, aborting")]
    BroadcastedPublicKeyError,

    #[error("DLog proof failed for party {party_index:?}")]
    DLogProofValidation { party_index: u16 },

    #[error("Ring pedersen proof failed for party {party_index:?}")]
    RingPedersenProofValidation { party_index: u16 },
}
