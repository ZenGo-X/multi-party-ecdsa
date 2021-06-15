use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::{FE, GE};

use paillier::EncryptionKey;
use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::Msg;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zk_paillier::zkproofs::DLogStatement;

use crate::protocols::multi_party_ecdsa::gg_2020::{self, orchestrate::*, ErrorType};

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
        let input_stage1 = KeyGenStage1Input {
            index: self.party_i as usize,
        };
        let keygen_stage1_res: KeyGenStage1Result = keygen_stage1(&input_stage1);

        output.push(Msg {
            sender: self.party_i.clone(),
            receiver: None,
            body: keygen_stage1_res.bc_com1_l.clone(),
        });
        Ok(Round1 {
            keygen_stage1_res,
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
    keygen_stage1_res: KeyGenStage1Result,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<gg_2020::party_i::KeyGenBroadcastMessage1>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<gg_2020::party_i::KeyGenDecommitMessage1>>,
    {
        output.push(Msg {
            sender: self.party_i.clone(),
            receiver: None,
            body: self.keygen_stage1_res.decom1_l.clone(),
        });
        Ok(Round2 {
            keys: self.keygen_stage1_res.party_keys_l,
            received_comm: input.into_vec_including_me(self.keygen_stage1_res.bc_com1_l),
            decom: self.keygen_stage1_res.decom1_l.clone(),

            party_i: self.party_i.clone(),
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<BroadcastMsgs<gg_2020::party_i::KeyGenBroadcastMessage1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round2 {
    keys: gg_2020::party_i::Keys,
    received_comm: Vec<gg_2020::party_i::KeyGenBroadcastMessage1>,
    decom: gg_2020::party_i::KeyGenDecommitMessage1,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<gg_2020::party_i::KeyGenDecommitMessage1>,
        mut output: O,
    ) -> Result<Round3>
    where
        O: Push<Msg<(VerifiableSS<GE>, FE)>>,
    {
        let params = gg_2020::party_i::Parameters {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let received_decom = input.into_vec_including_me(self.decom);

        let input_stage2 = KeyGenStage2Input {
            index: self.party_i as usize,
            params_s: params,
            party_keys_s: self.keys.clone(),
            decom1_vec_s: received_decom.clone(),
            bc1_vec_s: self.received_comm.clone(),
        };

        let res_stage2 =
            keygen_stage2(&input_stage2).map_err(ProceedError::Round2VerifyCommitments)?;

        for (i, share) in res_stage2.secret_shares_s.iter().enumerate() {
            if i + 1 == usize::from(self.party_i.clone()) {
                continue;
            }

            output.push(Msg {
                sender: self.party_i.clone(),
                receiver: Some(i as u16 + 1),
                body: (res_stage2.vss_scheme_s.clone(), share.clone()),
            })
        }

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),
            bc_vec: self.received_comm,

            own_vss: res_stage2.vss_scheme_s,
            own_share: res_stage2.secret_shares_s[usize::from(self.party_i.clone() - 1)],

            party_i: self.party_i.clone(),
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
    ) -> Store<BroadcastMsgs<gg_2020::party_i::KeyGenDecommitMessage1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round3 {
    keys: gg_2020::party_i::Keys,

    y_vec: Vec<GE>,
    bc_vec: Vec<gg_2020::party_i::KeyGenBroadcastMessage1>,

    own_vss: VerifiableSS<GE>,
    own_share: FE,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round3 {
    pub fn proceed<O>(self, input: P2PMsgs<(VerifiableSS<GE>, FE)>, mut output: O) -> Result<Round4>
    where
        O: Push<Msg<DLogProof<GE>>>,
    {
        let params = gg_2020::party_i::Parameters {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let (vss_schemes, party_shares): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((self.own_vss, self.own_share))
            .into_iter()
            .unzip();

        let input_stage3 = KeyGenStage3Input {
            party_keys_s: self.keys.clone(),
            vss_scheme_vec_s: vss_schemes,
            secret_shares_vec_s: party_shares,
            y_vec_s: self.y_vec.clone(),
            index_s: (self.party_i.clone() - 1) as usize,
            params_s: params,
        };

        let res_stage3 =
            keygen_stage3(&input_stage3).map_err(ProceedError::Round3VerifyVssConstruct)?;

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: res_stage3.dlog_proof_s.clone(),
        });

        Ok(Round4 {
            keys: self.keys.clone(),
            y_vec: self.y_vec.clone(),
            bc_vec: self.bc_vec,
            shared_keys: res_stage3.shared_keys_s.clone(),
            own_dlog_proof: res_stage3.dlog_proof_s.clone(),

            party_i: self.party_i.clone(),
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<(VerifiableSS<GE>, FE)>> {
        containers::P2PMsgsStore::new(i, n)
    }
}

pub struct Round4 {
    keys: gg_2020::party_i::Keys,
    y_vec: Vec<GE>,
    bc_vec: Vec<gg_2020::party_i::KeyGenBroadcastMessage1>,
    shared_keys: gg_2020::party_i::SharedKeys,
    own_dlog_proof: DLogProof<GE>,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round4 {
    pub fn proceed(self, input: BroadcastMsgs<DLogProof<GE>>) -> Result<LocalKey> {
        let params = gg_2020::party_i::Parameters {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let dlog_proofs = input.into_vec_including_me(self.own_dlog_proof.clone());

        let input_stage4 = KeyGenStage4Input {
            params_s: params.clone(),
            dlog_proof_vec_s: dlog_proofs,
            y_vec_s: self.y_vec.clone(),
        };

        let _ = keygen_stage4(&input_stage4).map_err(ProceedError::Round4VerifyDLogProof)?;

        let paillier_key_vec = (0..params.share_count)
            .map(|i| self.bc_vec[i as usize].e.clone())
            .collect::<Vec<EncryptionKey>>();
        let h1_h2_n_tilde_vec = self
            .bc_vec
            .iter()
            .map(|bc1| bc1.dlog_statement.clone())
            .collect::<Vec<DLogStatement>>();

        let (head, tail) = self.y_vec.split_at(1);
        let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

        let local_key = LocalKey {
            keys_additive: self.keys.clone(),
            keys_linear: self.shared_keys.clone(),
            paillier_key_vec,
            y_sum_s: y_sum,
            h1_h2_n_tilde_vec,

            i: self.party_i,
            t: self.t,
            n: self.n,
        };

        Ok(local_key)
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<DLogProof<GE>>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

/// Local secret obtained by party after [keygen](super::Keygen) protocol is completed
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalKey {
    pub keys_additive: gg_2020::party_i::Keys,
    pub keys_linear: gg_2020::party_i::SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub y_sum_s: GE,
    pub h1_h2_n_tilde_vec: Vec<DLogStatement>,
    pub i: u16,
    pub t: u16,
    pub n: u16,
}

impl LocalKey {
    /// Public key of secret shared between parties
    pub fn public_key(&self) -> GE {
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
