use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::BigInt;

use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::Msg;

use crate::utilities::mta::{MessageA, MessageB};

use crate::protocols::multi_party_ecdsa::gg_2020 as gg20;
use gg20::orchestrate::*;
use gg20::party_i::{
    LocalSignature, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SignatureRecid,
};
use gg20::state_machine::keygen::LocalKey;
use gg20::ErrorType;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GWI(pub GE);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GammaI(pub MessageB);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WI(pub MessageB);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeltaI(FE);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RDash(GE);

pub struct Round0 {
    /// Index of this party
    ///
    /// Must be in range `[0; n)` where `n` is number of parties involved in signing.
    pub i: u16,

    /// List of parties' indexes from keygen protocol
    ///
    /// I.e. `s_l[i]` must be an index of party `i` that was used by this party in keygen protocol.
    // s_l.len()` equals to `n` (number of parties involved in signing)
    pub s_l: Vec<u16>,

    /// Party local secret share
    pub local_key: LocalKey,
}

impl Round0 {
    /// Round 0 initiates two branches of protocol execution: [Round1] and [DecommitRound]. Both of
    /// them should be carried out simultaneously.
    pub fn proceed<O>(self, mut output: O) -> Result<(Round1, DecommitRound)>
    where
        O: Push<Msg<MessageA>> + Push<Msg<GWI>> + Push<Msg<SignBroadcastPhase1>>,
    {
        let input = &SignStage1Input {
            party_ek: self.local_key.paillier_ek.clone(),
            vss_scheme: self.local_key.vss_scheme.clone(),
            index: usize::from(self.s_l[usize::from(self.i - 1)]) - 1,
            s_l: self.s_l.iter().map(|&i| usize::from(i) - 1).collect(),
            shared_keys: self.local_key.keys_linear.clone(),
        };
        write_input(self.i, 1, &input);

        let stage1 = sign_stage1(&input);
        write_output(self.i, 1, &stage1);

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: stage1.m_a.0.clone(),
        });
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: GWI(stage1.sign_keys.g_w_i.clone()),
        });
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: stage1.bc1.clone(),
        });

        let decom_round = DecommitRound {
            i: self.i,
            com: stage1.bc1.clone(),
            decom: stage1.decom1.clone(),
        };
        let round1 = Round1 {
            i: self.i,
            s_l: self.s_l.clone(),
            local_key: self.local_key,

            stage1,
        };

        Ok((round1, decom_round))
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,

    stage1: SignStage1Result,
}

impl Round1 {
    pub fn proceed<O>(self, input: BroadcastMsgs<MessageA>, mut output: O) -> Result<Round2>
    where
        O: Push<Msg<(GammaI, WI)>>,
    {
        let m_a_vec = input.into_vec_including_me(self.stage1.m_a.0.clone());
        let input = SignStage2Input {
            m_a_vec,
            gamma_i: self.stage1.sign_keys.gamma_i,
            w_i: self.stage1.sign_keys.w_i,
            ek_vec: self.local_key.paillier_key_vec.clone(),
            index: usize::from(self.i - 1),
            l_ttag: self.s_l.len(),
            l_s: self
                .s_l
                .iter()
                .cloned()
                .map(|i| usize::from(i) - 1)
                .collect(),
        };

        write_input(self.i, 2, &input);
        let stage2 = sign_stage2(&input).map_err(Error::Round1)?;
        write_output(self.i, 2, &stage2);

        debug_assert_eq!(stage2.gamma_i_vec.len(), self.s_l.len() - 1);
        debug_assert_eq!(stage2.w_i_vec.len(), self.s_l.len() - 1);

        let party_indexes = (1..=self.s_l.len())
            .map(|j| u16::try_from(j).unwrap())
            .filter(|&j| j != self.i);
        let gammas = stage2.gamma_i_vec.iter().map(|(m_b, _)| m_b);
        let ws = stage2.w_i_vec.iter().map(|(m_b, _)| m_b);
        for (j, (gamma_i, w_i)) in party_indexes.zip(gammas.zip(ws)) {
            output.push(Msg {
                sender: self.i,
                receiver: Some(j),
                body: (GammaI(gamma_i.clone()), WI(w_i.clone())),
            });
        }

        Ok(Round2 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,

            stage1: self.stage1,
            stage2,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<MessageA>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round2 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,

    stage1: SignStage1Result,
    stage2: SignStage2Result,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input_round0: BroadcastMsgs<GWI>,
        input_round1: P2PMsgs<(GammaI, WI)>,
        mut output: O,
    ) -> Result<CompletedRound2>
    where
        O: Push<Msg<DeltaI>>,
    {
        let g_w_i_s = input_round0
            .into_vec_including_me(GWI(self.stage1.sign_keys.g_w_i))
            .into_iter()
            .map(|GWI(g_w_i)| g_w_i)
            .collect();
        let (m_b_gamma_s, m_b_w_s): (Vec<_>, Vec<_>) = input_round1
            .into_vec()
            .into_iter()
            .map(|(gamma_i, w_i)| (gamma_i.0, w_i.0))
            .unzip();

        let input = SignStage3Input {
            dk_s: self.local_key.paillier_dk.clone(),
            k_i_s: self.stage1.sign_keys.k_i,
            m_b_gamma_s: m_b_gamma_s.clone(),
            m_b_w_s,
            g_w_i_s,
            index_s: usize::from(self.i) - 1,
            ttag_s: self.s_l.len(),
        };

        write_input(self.i, 3, &input);
        let stage3 = sign_stage3(&input).map_err(Error::Round2Stage3)?;
        write_output(self.i, 3, &stage3);

        let input = SignStage4Input {
            alpha_vec_s: stage3.alpha_vec_gamma.clone(),
            beta_vec_s: self
                .stage2
                .gamma_i_vec
                .iter()
                .map(|(_, s)| s)
                .cloned()
                .collect(),
            miu_vec_s: stage3.alpha_vec_w.clone(),
            ni_vec_s: self
                .stage2
                .w_i_vec
                .iter()
                .map(|(_, s)| s)
                .cloned()
                .collect(),
            sign_keys_s: self.stage1.sign_keys.clone(),
        };

        write_input(self.i, 4, &input);
        let stage4 = sign_stage4(&input).map_err(Error::Round2Stage4)?;
        write_output(self.i, 4, &stage4);

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: DeltaI(stage4.delta_i),
        });

        Ok(CompletedRound2 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,

            mb_gamma_s: m_b_gamma_s,

            stage1: self.stage1,
            stage2: self.stage2,
            stage3,
            stage4,
        })
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> (Store<BroadcastMsgs<GWI>>, Store<P2PMsgs<(GammaI, WI)>>) {
        (
            containers::BroadcastMsgsStore::new(i, n),
            containers::P2PMsgsStore::new(i, n),
        )
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct CompletedRound2 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,

    mb_gamma_s: Vec<MessageB>,

    stage1: SignStage1Result,
    stage2: SignStage2Result,
    stage3: SignStage3Result,
    stage4: SignStage4Result,
}

/// Round3 starts after finishing round2 (see [CompletedRound2]) and receiving all the commitments
/// (see [Commitments]). Use method [new](Round3::new) to construct a round.
pub struct Round3 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,

    commitments: Vec<SignBroadcastPhase1>,
    mb_gamma_s: Vec<MessageB>,

    stage1: SignStage1Result,
    stage2: SignStage2Result,
    stage3: SignStage3Result,
    stage4: SignStage4Result,
}

impl Round3 {
    pub fn new(round2: CompletedRound2, commitments: Commitments) -> Self {
        Self {
            i: round2.i,
            s_l: round2.s_l,
            local_key: round2.local_key,

            commitments: commitments.commitments,
            mb_gamma_s: round2.mb_gamma_s,

            stage1: round2.stage1,
            stage2: round2.stage2,
            stage3: round2.stage3,
            stage4: round2.stage4,
        }
    }

    pub fn proceed<O>(
        self,
        input_decom: BroadcastMsgs<SignDecommitPhase1>,
        input_delta: BroadcastMsgs<DeltaI>,
        mut output: O,
    ) -> Result<Round4>
    where
        O: Push<Msg<RDash>>,
    {
        let decom_vec1 = input_decom.into_vec_including_me(self.stage1.decom1.clone());
        let deltas: Vec<_> = input_delta
            .into_vec_including_me(DeltaI(self.stage4.delta_i.clone()))
            .into_iter()
            .map(|DeltaI(d)| d)
            .collect();
        let delta_inv = SignKeys::phase3_reconstruct_delta(&deltas);

        let input = SignStage5Input {
            m_b_gamma_vec: self.mb_gamma_s,
            delta_inv,
            decom_vec1,
            bc1_vec: self.commitments,
            index: usize::from(self.i) - 1,
            sign_keys: self.stage1.sign_keys.clone(),
            s_ttag: self.s_l.len(),
        };

        write_input(self.i, 5, &input);
        let stage5 = sign_stage5(&input).map_err(Error::Round3)?;
        write_output(self.i, 5, &stage5);

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: RDash(stage5.R_dash),
        });

        Ok(Round4 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,

            stage1: self.stage1,
            stage2: self.stage2,
            stage3: self.stage3,
            stage4: self.stage4,
            stage5,
        })
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> (
        Store<BroadcastMsgs<SignDecommitPhase1>>,
        Store<BroadcastMsgs<DeltaI>>,
    ) {
        (
            containers::BroadcastMsgsStore::new(i, n),
            containers::BroadcastMsgsStore::new(i, n),
        )
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round4 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,

    stage1: SignStage1Result,
    stage2: SignStage2Result,
    stage3: SignStage3Result,
    stage4: SignStage4Result,
    stage5: SignStage5Result,
}

impl Round4 {
    pub fn proceed(self, input: BroadcastMsgs<RDash>) -> Result<CompletedOfflineStage> {
        let r_dash = input.into_vec_including_me(RDash(self.stage5.R_dash.clone()));
        let r_dash = r_dash.into_iter().map(|RDash(r)| r).collect();
        Ok(CompletedOfflineStage {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,

            stage1: self.stage1,
            stage2: self.stage2,
            stage3: self.stage3,
            stage4: self.stage4,
            stage5: self.stage5,

            r_dash,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<RDash>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct CompletedOfflineStage {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey,

    stage1: SignStage1Result,
    stage2: SignStage2Result,
    stage3: SignStage3Result,
    stage4: SignStage4Result,
    stage5: SignStage5Result,

    r_dash: Vec<GE>,
}

impl CompletedOfflineStage {
    pub fn public_key(&self) -> &GE {
        &self.local_key.y_sum_s
    }
}

pub struct Round5 {
    message_bn: BigInt,
    offline: CompletedOfflineStage,
}

impl Round5 {
    pub fn new(message_bn: BigInt, offline: CompletedOfflineStage) -> Self {
        Self {
            message_bn,
            offline,
        }
    }

    pub fn proceed_manual(self) -> Result<(Round6, LocalSignature)> {
        println!(
            "S_L = {:?}, INDEX = {}",
            self.offline.s_l,
            usize::from(self.offline.s_l[usize::from(self.offline.i) - 1]) - 1
        );
        let input = SignStage6Input {
            R_dash_vec: self.offline.r_dash,
            R: self.offline.stage5.R,
            m_a: self.offline.stage1.m_a.0,
            e_k: self.offline.local_key.paillier_key_vec
                [usize::from(self.offline.s_l[usize::from(self.offline.i) - 1]) - 1]
                .clone(),
            k_i: self.offline.stage1.sign_keys.k_i,
            randomness: self.offline.stage1.m_a.1,
            h1_h2_N_tilde_vec: self.offline.local_key.h1_h2_n_tilde_vec,
            index: usize::from(self.offline.i) - 1,
            s: self
                .offline
                .s_l
                .into_iter()
                .map(|i| usize::from(i) - 1)
                .collect(),
            ysum: self.offline.local_key.y_sum_s,
            sigma: self.offline.stage4.sigma_i,
            sign_key: self.offline.stage1.sign_keys.clone(),
            message_bn: self.message_bn,
        };

        write_input(self.offline.i, 6, &input);
        let stage6 = sign_stage6(&input).map_err(Error::Round5)?;
        write_output(self.offline.i, 6, &stage6);

        Ok((
            Round6 {
                i: self.offline.i,
                y_sum: self.offline.local_key.y_sum_s.clone(),
                // local_signature: stage6.local_sig.clone(),
            },
            stage6.local_sig,
        ))
    }

    // pub fn proceed<O>(self, mut output: O) -> Result<Round6>
    // where
    //     O: Push<Msg<LocalSignature>>,
    // {
    //     let i = self.offline.i;
    //     let (next_state, msg) = self.proceed_manual()?;
    //
    //     output.push(Msg {
    //         sender: i,
    //         receiver: None,
    //         body: msg,
    //     });
    //
    //     Ok(next_state)
    // }
    //
    // pub fn is_expensive(&self) -> bool {
    //     true
    // }
}

pub struct Round6 {
    i: u16,
    y_sum: GE,
    // local_signature: LocalSignature,
}

impl Round6 {
    pub fn proceed_manual(self, sigs: Vec<LocalSignature>) -> Result<SignatureRecid> {
        let input = SignStage7Input {
            local_sig_vec: sigs,
            ysum: self.y_sum,
        };

        write_input(self.i, 7, &input);
        let output = sign_stage7(&input)
            .map(|s| s.local_sig)
            .map_err(Error::Round6)?;
        write_output(self.i, 7, &output);

        Ok(output)
    }

    // pub fn proceed(self, input: BroadcastMsgs<LocalSignature>) -> Result<SignatureRecid> {
    //     let sigs = input.into_vec_including_me(self.local_signature.clone());
    //     self.proceed_manual(sigs)
    // }

    // pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<LocalSignature>> {
    //     containers::BroadcastMsgsStore::new(i, n)
    // }

    // pub fn is_expensive(&self) -> bool {
    //     true
    // }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("round 1: {0:?}")]
    Round1(ErrorType),
    #[error("round 2 stage 3: {0:?}")]
    Round2Stage3(crate::Error),
    #[error("round 2 stage 4: {0:?}")]
    Round2Stage4(ErrorType),
    #[error("round 3: {0:?}")]
    Round3(ErrorType),
    #[error("round 5: {0:?}")]
    Round5(ErrorType),
    #[error("round 6: {0:?}")]
    Round6(ErrorType),
}

/// Round that published decommit message once all commits from all the parties were received
pub struct DecommitRound {
    i: u16,
    com: SignBroadcastPhase1,
    decom: SignDecommitPhase1,
}

impl DecommitRound {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<SignBroadcastPhase1>,
        mut output: O,
    ) -> Result<Commitments>
    where
        O: Push<Msg<SignDecommitPhase1>>,
    {
        let commitments = input.into_vec_including_me(self.com.clone());

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: self.decom,
        });

        Ok(Commitments { commitments })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<SignBroadcastPhase1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        false
    }
}

/// Produced when [DecommitRound] is finished
pub struct Commitments {
    commitments: Vec<SignBroadcastPhase1>,
}

#[cfg(test)]
fn write_input<T: Serialize>(party_i: u16, stage: u16, input: &T) {
    if let Some(file_name) = std::env::var_os("WRITE_FILE") {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut json_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .unwrap();
        writeln!(json_file, "Party {} stage {} input:", party_i, stage).unwrap();
        writeln!(
            json_file,
            "{}",
            serde_json::to_string_pretty(input).unwrap()
        )
        .unwrap();
    }
}
#[cfg(test)]
fn write_output<T: Serialize>(party_i: u16, stage: u16, output: &T) {
    if let Some(file_name) = std::env::var_os("WRITE_FILE") {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut json_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_name)
            .unwrap();
        writeln!(json_file, "Party {} stage {} output:", party_i, stage).unwrap();
        writeln!(
            json_file,
            "{}",
            serde_json::to_string_pretty(output).unwrap()
        )
        .unwrap();
    }
}
#[cfg(not(test))]
fn write_input<T: Serialize>(_party_i: u16, _stage: u16, _input: &T) {}
#[cfg(not(test))]
fn write_output<T: Serialize>(_party_i: u16, _stage: u16, _output: &T) {}
