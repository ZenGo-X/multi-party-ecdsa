use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use sha2::Sha256;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use paillier::EncryptionKey;
use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::Msg;
use zk_paillier::zkproofs::DLogStatement;

use crate::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys,
};
use crate::protocols::multi_party_ecdsa::gg_2020::{self, ErrorType};

pub struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<gg_2020::party_i::KeyGenBroadcastMessage1>>,
    {
        let party_keys = Keys::create(self.party_i as usize);
        let (bc1, decom1) =
            party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: bc1.clone(),
        });
        Ok(Round1 {
            keys: party_keys,
            bc1,
            decom1,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    keys: Keys,
    bc1: KeyGenBroadcastMessage1,
    decom1: KeyGenDecommitMessage1,
    party_i: u16,
    t: u16,
    n: u16,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenBroadcastMessage1>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<gg_2020::party_i::KeyGenDecommitMessage1>>,
    {
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: self.decom1.clone(),
        });
        Ok(Round2 {
            keys: self.keys,
            received_comm: input.into_vec_including_me(self.bc1),
            decom: self.decom1,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenBroadcastMessage1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round2 {
    keys: gg_2020::party_i::Keys,
    received_comm: Vec<KeyGenBroadcastMessage1>,
    decom: KeyGenDecommitMessage1,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenDecommitMessage1>,
        mut output: O,
    ) -> Result<Round3>
    where
        O: Push<Msg<(VerifiableSS<Secp256k1>, Scalar<Secp256k1>)>>,
    {
        let params = gg_2020::party_i::Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let received_decom = input.into_vec_including_me(self.decom);

        let vss_result = self
            .keys
            .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
                &params,
                &received_decom,
                &self.received_comm,
            )
            .map_err(ProceedError::Round2VerifyCommitments)?;

        for (i, share) in vss_result.1.iter().enumerate() {
            if i + 1 == usize::from(self.party_i) {
                continue;
            }

            output.push(Msg {
                sender: self.party_i,
                receiver: Some(i as u16 + 1),
                body: (vss_result.0.clone(), share.clone()),
            })
        }

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),
            bc_vec: self.received_comm,

            own_vss: vss_result.0.clone(),
            own_share: vss_result.1[usize::from(self.party_i - 1)].clone(),

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenDecommitMessage1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round3 {
    keys: gg_2020::party_i::Keys,

    y_vec: Vec<Point<Secp256k1>>,
    bc_vec: Vec<gg_2020::party_i::KeyGenBroadcastMessage1>,

    own_vss: VerifiableSS<Secp256k1>,
    own_share: Scalar<Secp256k1>,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<(VerifiableSS<Secp256k1>, Scalar<Secp256k1>)>,
        mut output: O,
    ) -> Result<Round4>
    where
        O: Push<Msg<DLogProof<Secp256k1, Sha256>>>,
    {
        let params = gg_2020::party_i::Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let (vss_schemes, party_shares): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((self.own_vss, self.own_share))
            .into_iter()
            .unzip();

        let (shared_keys, dlog_proof) = self
            .keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &params,
                &self.y_vec,
                &party_shares,
                &vss_schemes,
                self.party_i.into(),
            )
            .map_err(ProceedError::Round3VerifyVssConstruct)?;

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: dlog_proof.clone(),
        });

        Ok(Round4 {
            keys: self.keys.clone(),
            y_vec: self.y_vec.clone(),
            bc_vec: self.bc_vec,
            shared_keys,
            own_dlog_proof: dlog_proof,
            vss_vec: vss_schemes,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<P2PMsgs<(VerifiableSS<Secp256k1>, Scalar<Secp256k1>)>> {
        containers::P2PMsgsStore::new(i, n)
    }
}

pub struct Round4 {
    keys: gg_2020::party_i::Keys,
    y_vec: Vec<Point<Secp256k1>>,
    bc_vec: Vec<gg_2020::party_i::KeyGenBroadcastMessage1>,
    shared_keys: gg_2020::party_i::SharedKeys,
    own_dlog_proof: DLogProof<Secp256k1, Sha256>,
    vss_vec: Vec<VerifiableSS<Secp256k1>>,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round4 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<DLogProof<Secp256k1, Sha256>>,
    ) -> Result<LocalKey<Secp256k1>> {
        let params = gg_2020::party_i::Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let dlog_proofs = input.into_vec_including_me(self.own_dlog_proof.clone());

        Keys::verify_dlog_proofs_check_against_vss(
            &params,
            &dlog_proofs,
            &self.y_vec,
            &self.vss_vec,
        )
        .map_err(ProceedError::Round4VerifyDLogProof)?;
        let pk_vec = (0..params.share_count as usize)
            .map(|i| dlog_proofs[i].pk.clone())
            .collect::<Vec<Point<Secp256k1>>>();

        let paillier_key_vec = (0..params.share_count)
            .map(|i| self.bc_vec[i as usize].e.clone())
            .collect::<Vec<EncryptionKey>>();
        let h1_h2_n_tilde_vec = self
            .bc_vec
            .iter()
            .map(|bc1| bc1.dlog_statement.clone())
            .collect::<Vec<DLogStatement>>();

        let (head, tail) = self.y_vec.split_at(1);
        let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

        let local_key = LocalKey {
            paillier_dk: self.keys.dk,
            pk_vec,

            keys_linear: self.shared_keys.clone(),
            paillier_key_vec,
            y_sum_s: y_sum,
            h1_h2_n_tilde_vec,

            vss_scheme: self.vss_vec[usize::from(self.party_i - 1)].clone(),

            i: self.party_i,
            t: self.t,
            n: self.n,
        };

        Ok(local_key)
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<DLogProof<Secp256k1, Sha256>>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

/// Local secret obtained by party after [keygen](super::Keygen) protocol is completed
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocalKey<E: Curve> {
    pub paillier_dk: paillier::DecryptionKey,
    pub pk_vec: Vec<Point<E>>,
    pub keys_linear: gg_2020::party_i::SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub y_sum_s: Point<E>,
    pub h1_h2_n_tilde_vec: Vec<DLogStatement>,
    pub vss_scheme: VerifiableSS<E>,
    pub i: u16,
    pub t: u16,
    pub n: u16,
}

impl LocalKey<Secp256k1> {
    /// Public key of secret shared between parties
    pub fn public_key(&self) -> Point<Secp256k1> {
        self.y_sum_s.clone()
    }
}

// Errors

type Result<T> = std::result::Result<T, ProceedError>;

/// Proceeding protocol error
///
/// Subset of [keygen errors](enum@super::Error) that can occur at protocol proceeding (i.e. after
/// every message was received and pre-validated).
#[derive(Debug, Error)]
pub enum ProceedError {
    #[error("round 2: verify commitments: {0:?}")]
    Round2VerifyCommitments(ErrorType),
    #[error("round 3: verify vss construction: {0:?}")]
    Round3VerifyVssConstruct(ErrorType),
    #[error("round 4: verify dlog proof: {0:?}")]
    Round4VerifyDLogProof(ErrorType),
}
