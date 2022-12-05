use thiserror::Error;

pub type FsDkrResult<T> = Result<T, FsDkrError>;

#[derive(Error, Debug)]
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

    #[error("SizeMismatch error for the refresh message {refresh_message_index:?} - Fairness proof length: {fairness_proof_len:?}, Points Commited Length: {points_commited_len:?}, Points Encrypted Length: {points_encrypted_len:?}")]
    SizeMismatchError {
        refresh_message_index: usize,
        fairness_proof_len: usize,
        points_commited_len: usize,
        points_encrypted_len: usize,
    },

    #[error("Fairness proof verification failed, results - T_add_e_Y == z_G: {t_add_eq_z_g:?} - e_u_add_c_e == enc_z_w: {e_u_add_eq_z_w:?}")]
    FairnessProof {
        t_add_eq_z_g: bool,
        e_u_add_eq_z_w: bool,
    },

    #[error("Paillier verification proof failed for party {party_index:?}")]
    PaillierVerificationError { party_index: usize },

    #[error("A new party did not receive a valid index.")]
    NewPartyUnassignedIndexError,

    #[error("The broadcasted public key is not the same from everyone, aborting")]
    BroadcastedPublicKeyError,

    #[error("DLog proof failed for party {party_index:?}")]
    DLogProofValidation { party_index: usize },
}
