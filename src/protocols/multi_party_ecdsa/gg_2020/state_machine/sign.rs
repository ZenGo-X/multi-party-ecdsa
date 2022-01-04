//! # High-level threshold signing protocol implementation
//!
//! Key feature of GG20 protocol is one-round online signing, meaning that every party needs to
//! broadcast just a single message to sign a data. However, it still requires completing an offline
//! computation for fixed set of parties
//!
//! ## How to get things work
//!
//! First of all, parties need to carry out distributed key generation protocol (see [keygen module]).
//! After DKG is successfully completed, it outputs [LocalKey] — a party local secret share.
//! Then you fix a set of parties who will participate in threshold signing, and they run
//! [OfflineStage] protocol. `OfflineStage` implements [StateMachine] and can be executed in the same
//! way as [Keygen]. `OfflineStage` outputs a [CompletedOfflineStage]. [SignManual] takes a
//! `CompletedOfflineStage` and allows you to perform one-round signing. It doesn't implement
//! `StateMachine`, but rather provides methods to construct messages and final signature manually
//! (refer to [SignManual] documentation to see how to use it).
//!
//! [keygen module]: super::keygen
//! [Keygen]: super::keygen::Keygen
//! [LocalKey]: super::keygen::LocalKey
//! [StateMachine]: round_based::StateMachine

use std::convert::TryFrom;
use std::mem::replace;
use std::time::Duration;

use round_based::containers::{push::Push, BroadcastMsgs, MessageStore, P2PMsgs, Store, StoreErr};
use round_based::{IsCritical, Msg, StateMachine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::utilities::mta::MessageA;

use crate::protocols::multi_party_ecdsa::gg_2020 as gg20;
use curv::elliptic::curves::secp256_k1::Secp256k1;
use gg20::party_i::{SignBroadcastPhase1, SignDecommitPhase1, SignatureRecid};
use gg20::state_machine::keygen::LocalKey;

mod fmt;
mod rounds;

use crate::utilities::zk_pdl_with_slack::PDLwSlackProof;
use curv::BigInt;
use rounds::*;
pub use rounds::{CompletedOfflineStage, Error as ProceedError, PartialSignature};

/// Offline Stage of GG20 signing
///
/// Successfully carried out Offline Stage will produce [CompletedOfflineStage] that can
/// be used for one-round signing multiple times.
pub struct OfflineStage {
    round: OfflineR,

    msgs1: Option<Store<BroadcastMsgs<(MessageA, SignBroadcastPhase1)>>>,
    msgs2: Option<Store<P2PMsgs<(GammaI, WI)>>>,
    msgs3: Option<Store<BroadcastMsgs<(DeltaI, TI, TIProof)>>>,
    msgs4: Option<Store<BroadcastMsgs<SignDecommitPhase1>>>,
    msgs5: Option<Store<BroadcastMsgs<(RDash, Vec<PDLwSlackProof>)>>>,
    msgs6: Option<Store<BroadcastMsgs<(SI, HEGProof)>>>,

    msgs_queue: MsgQueue,

    party_i: u16,
    party_n: u16,
}

impl OfflineStage {
    /// Construct a party of offline stage of threshold signing protocol
    ///
    /// Once offline stage is finished, parties can do one-round threshold signing (i.e. they only
    /// need to exchange a single set of messages).
    ///
    /// Takes party index `i` (in range `[1; n]`), list `s_l` of parties' indexes from keygen protocol
    /// (`s_l[i]` must be an index of party `i` that was used by this party in keygen protocol), and
    /// party local secret share `local_key`.
    ///
    /// Returns error if given arguments are contradicting.
    pub fn new(i: u16, s_l: Vec<u16>, local_key: LocalKey<Secp256k1>) -> Result<Self> {
        if s_l.len() < 2 {
            return Err(Error::TooFewParties);
        }
        if i == 0 || usize::from(i) > s_l.len() {
            return Err(Error::InvalidPartyIndex);
        }

        let keygen_n = local_key.n;
        if s_l.iter().any(|&i| i == 0 || i > keygen_n) {
            return Err(Error::InvalidSl);
        }
        {
            // Check if s_l has duplicates
            let mut s_l_sorted = s_l.clone();
            s_l_sorted.sort_unstable();
            let mut s_l_sorted_deduped = s_l_sorted.clone();
            s_l_sorted_deduped.dedup();

            if s_l_sorted != s_l_sorted_deduped {
                return Err(Error::InvalidSl);
            }
        }

        let n = u16::try_from(s_l.len()).map_err(|_| Error::TooManyParties { n: s_l.len() })?;

        Ok(Self {
            round: OfflineR::R0(Round0 { i, s_l, local_key }),

            msgs1: Some(Round1::expects_messages(i, n)),
            msgs2: Some(Round2::expects_messages(i, n)),
            msgs3: Some(Round3::expects_messages(i, n)),
            msgs4: Some(Round4::expects_messages(i, n)),
            msgs5: Some(Round5::expects_messages(i, n)),
            msgs6: Some(Round6::expects_messages(i, n)),

            msgs_queue: MsgQueue(vec![]),

            party_i: i,
            party_n: n,
        })
    }

    // fn proceed_state(&mut self, may_block: bool) -> Result<()> {
    //     self.proceed_round(may_block)?;
    //     self.proceed_decommit_round(may_block)
    // }

    fn proceed_round(&mut self, may_block: bool) -> Result<()> {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store5_wants_more = self.msgs5.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store6_wants_more = self.msgs6.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        let next_state: OfflineR;
        let try_again: bool = match replace(&mut self.round, OfflineR::Gone) {
            OfflineR::R0(round) if !round.is_expensive() || may_block => {
                next_state = round
                    .proceed(&mut self.msgs_queue)
                    .map(OfflineR::R1)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ OfflineR::R0(_) => {
                next_state = s;
                false
            }
            OfflineR::R1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs1.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R2)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ OfflineR::R1(_) => {
                next_state = s;
                false
            }
            OfflineR::R2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs2.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R3)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ OfflineR::R2(_) => {
                next_state = s;
                false
            }
            OfflineR::R3(round) if !store3_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs3.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R4)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ OfflineR::R3(_) => {
                next_state = s;
                false
            }
            OfflineR::R4(round) if !store4_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs4.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R5)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ OfflineR::R4(_) => {
                next_state = s;
                false
            }
            OfflineR::R5(round) if !store5_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs5.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R6)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ OfflineR::R5(_) => {
                next_state = s;
                false
            }
            OfflineR::R6(round) if !store6_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs6.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs)
                    .map(OfflineR::Finished)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ OfflineR::R6(_) => {
                next_state = s;
                false
            }
            s @ OfflineR::Finished(_) | s @ OfflineR::Gone => {
                next_state = s;
                false
            }
        };

        self.round = next_state;
        if try_again {
            self.proceed_round(may_block)
        } else {
            Ok(())
        }
    }
}

impl StateMachine for OfflineStage {
    type MessageBody = OfflineProtocolMessage;
    type Err = Error;
    type Output = CompletedOfflineStage;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
        let current_round = self.current_round();

        match msg.body {
            OfflineProtocolMessage(OfflineM::M1(m)) => {
                let store = self
                    .msgs1
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 1,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M2(m)) => {
                let store = self
                    .msgs2
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M3(m)) => {
                let store = self
                    .msgs3
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M4(m)) => {
                let store = self
                    .msgs4
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M5(m)) => {
                let store = self
                    .msgs5
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M6(m)) => {
                let store = self
                    .msgs6
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
        }
        self.proceed_round(false)
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue.0
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store5_wants_more = self.msgs5.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store6_wants_more = self.msgs6.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        match &self.round {
            OfflineR::R0(_) => true,
            OfflineR::R1(_) => !store1_wants_more,
            OfflineR::R2(_) => !store2_wants_more,
            OfflineR::R3(_) => !store3_wants_more,
            OfflineR::R4(_) => !store4_wants_more,
            OfflineR::R5(_) => !store5_wants_more,
            OfflineR::R6(_) => !store6_wants_more,
            OfflineR::Finished(_) | OfflineR::Gone => false,
        }
    }

    fn proceed(&mut self) -> Result<(), Self::Err> {
        self.proceed_round(true)
    }

    fn round_timeout(&self) -> Option<Duration> {
        None
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        panic!("no timeout was set")
    }

    fn is_finished(&self) -> bool {
        matches!(&self.round, OfflineR::Finished(_))
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>> {
        match self.round {
            OfflineR::Finished(_) => (),
            OfflineR::Gone => return Some(Err(Error::DoublePickOutput)),
            _ => return None,
        }

        match replace(&mut self.round, OfflineR::Gone) {
            OfflineR::Finished(result) => Some(Ok(result)),
            _ => unreachable!("guaranteed by match expression above"),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            OfflineR::R0(_) => 0,
            OfflineR::R1(_) => 1,
            OfflineR::R2(_) => 2,
            OfflineR::R3(_) => 3,
            OfflineR::R4(_) => 4,
            OfflineR::R5(_) => 5,
            OfflineR::R6(_) => 6,
            OfflineR::Finished(_) | OfflineR::Gone => 7,
        }
    }

    fn total_rounds(&self) -> Option<u16> {
        Some(6)
    }

    fn party_ind(&self) -> u16 {
        self.party_i
    }

    fn parties(&self) -> u16 {
        self.party_n
    }
}

impl super::traits::RoundBlame for OfflineStage {
    /// RoundBlame returns number of unwilling parties and a vector of their party indexes.
    fn round_blame(&self) -> (u16, Vec<u16>) {
        let store1_blame = self.msgs1.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store2_blame = self.msgs2.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store3_blame = self.msgs3.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store4_blame = self.msgs4.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store5_blame = self.msgs5.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store6_blame = self.msgs6.as_ref().map(|s| s.blame()).unwrap_or_default();

        let default = (0, vec![]);
        match &self.round {
            OfflineR::R0(_) => default,
            OfflineR::R1(_) => store1_blame,
            OfflineR::R2(_) => store2_blame,
            OfflineR::R3(_) => store3_blame,
            OfflineR::R4(_) => store4_blame,
            OfflineR::R5(_) => store5_blame,
            OfflineR::R6(_) => store6_blame,
            OfflineR::Finished(_) => store6_blame,
            OfflineR::Gone => default,
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum OfflineR {
    R0(Round0),
    R1(Round1),
    R2(Round2),
    R3(Round3),
    R4(Round4),
    R5(Round5),
    R6(Round6),
    Finished(CompletedOfflineStage),
    Gone,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OfflineProtocolMessage(OfflineM);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum OfflineM {
    M1((MessageA, SignBroadcastPhase1)),
    M2((GammaI, WI)),
    M3((DeltaI, TI, TIProof)),
    M4(SignDecommitPhase1),
    M5((RDash, Vec<PDLwSlackProof>)),
    M6((SI, HEGProof)),
}

struct MsgQueue(Vec<Msg<OfflineProtocolMessage>>);

macro_rules! make_pushable {
    ($($constructor:ident $t:ty),*$(,)?) => {
        $(
        impl Push<Msg<$t>> for MsgQueue {
            fn push(&mut self, m: Msg<$t>) {
                Vec::push(&mut self.0, Msg{
                    sender: m.sender,
                    receiver: m.receiver,
                    body: OfflineProtocolMessage(OfflineM::$constructor(m.body))
                })
            }
        }
        )*
    };
}

make_pushable! {
    M1 (MessageA, SignBroadcastPhase1),
    M2 (GammaI, WI),
    M3 (DeltaI, TI, TIProof),
    M4 SignDecommitPhase1,
    M5 (RDash, Vec<PDLwSlackProof>),
    M6 (SI, HEGProof),
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    /// Too few parties (`n < 2`)
    #[error("at least 2 parties are required for signing")]
    TooFewParties,
    /// Too many parties. `n` must fit into `u16`, so only `n < u16::MAX` values are supported.
    #[error("too many parties: n={n}, n must be less than 2^16")]
    TooManyParties { n: usize },
    /// Party index `i` is not in range `[1; n]`
    #[error("party index is not in range [1; n]")]
    InvalidPartyIndex,
    /// List `s_l` is invalid. Either it contains duplicates (`exist i j. i != j && s_l[i] = s_l[j]`),
    /// or contains index that is not in the range `[1; keygen_n]`, `keygen_n` — number of parties
    /// participated in DKG (`exist i. s_l[i] = 0 || s_l[i] > keygen_n`).
    #[error("invalid s_l")]
    InvalidSl,

    /// Round proceeding resulted in protocol error
    #[error("proceeding round: {0}")]
    ProceedRound(rounds::Error),

    /// Received message which we didn't expect to receive now (e.g. message from previous round)
    #[error(
        "didn't expect to receive message from round {msg_round} (being at round {current_round})"
    )]
    ReceivedOutOfOrderMessage { current_round: u16, msg_round: u16 },
    /// Received message didn't pass pre-validation
    #[error("received message didn't pass pre-validation: {0}")]
    HandleMessage(#[source] StoreErr),

    /// [OfflineStage::pick_output] called twice
    #[error("pick_output called twice")]
    DoublePickOutput,

    /// A bug in protocol implementation
    #[error("offline stage protocol bug: {0}")]
    Bug(InternalError),
}

#[derive(Debug, Error)]
pub enum InternalError {
    #[error("store gone")]
    StoreGone,
    #[error("store reported that it's collected all the messages it needed, but refused to give received messages")]
    RetrieveMessagesFromStore(StoreErr),
    #[error("decommit round expected to be in NotStarted state")]
    DecommitRoundWasntInInitialState,
}

impl From<InternalError> for Error {
    fn from(err: InternalError) -> Self {
        Error::Bug(err)
    }
}

impl IsCritical for Error {
    fn is_critical(&self) -> bool {
        match self {
            Error::TooFewParties => true,
            Error::TooManyParties { .. } => true,
            Error::InvalidPartyIndex => true,
            Error::InvalidSl => true,
            Error::ProceedRound(_) => true,
            Error::ReceivedOutOfOrderMessage { .. } => false,
            Error::HandleMessage(_) => false,
            Error::DoublePickOutput => true,
            Error::Bug(_) => true,
        }
    }
}

/// Manual GG20 signing
///
/// After you completed [OfflineStage] and got [CompletedOfflineStage], parties can perform signing
/// simply by broadcasting a single message.
///
/// ## Example
/// ```no_run
/// # use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
/// #     state_machine::sign::{CompletedOfflineStage, SignManual, PartialSignature},
/// #     party_i::{LocalSignature, verify},
/// # };
/// # use curv::arithmetic::{BigInt, Converter};
/// # type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
/// # fn broadcast(msg: PartialSignature) -> Result<()> { panic!() }
/// # fn wait_messages() -> Result<Vec<PartialSignature>> { panic!() }
/// # fn main() -> Result<()> {
/// # let completed_offline_stage: CompletedOfflineStage = panic!();
/// let data = BigInt::from_bytes(b"a message");
///
/// // Sign a message locally
/// let (sign, msg) = SignManual::new(data.clone(), completed_offline_stage)?;
/// // Broadcast local partial signature
/// broadcast(msg)?;
/// // Collect partial signatures from other parties
/// let sigs: Vec<PartialSignature> = wait_messages()?;
/// // Complete signing
/// let signature = sign.complete(&sigs)?;
/// // Verify that signature matches joint public key
/// assert!(verify(&signature, completed_offline_stage.public_key(), &data).is_ok());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SignManual {
    state: Round7,
}

impl SignManual {
    pub fn new(
        message: BigInt,
        completed_offline_stage: CompletedOfflineStage,
    ) -> Result<(Self, PartialSignature), SignError> {
        Round7::new(&message, completed_offline_stage)
            .map(|(state, m)| (Self { state }, m))
            .map_err(SignError::LocalSigning)
    }

    /// `sigs` must not include partial signature produced by local party (only partial signatures produced
    /// by other parties)
    pub fn complete(self, sigs: &[PartialSignature]) -> Result<SignatureRecid, SignError> {
        self.state
            .proceed_manual(sigs)
            .map_err(SignError::CompleteSigning)
    }
}

#[derive(Debug, Error)]
pub enum SignError {
    #[error("signing message locally: {0}")]
    LocalSigning(rounds::Error),
    #[error("couldn't complete signing: {0}")]
    CompleteSigning(rounds::Error),
}

#[cfg(test)]
mod test {
    use curv::arithmetic::Converter;
    use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
    use round_based::dev::Simulation;
    use sha2::Sha256;

    use super::*;
    use gg20::party_i::verify;
    use gg20::state_machine::keygen::test::simulate_keygen;

    fn simulate_offline_stage(
        local_keys: Vec<LocalKey<Secp256k1>>,
        s_l: &[u16],
    ) -> Vec<CompletedOfflineStage> {
        let mut simulation = Simulation::new();
        simulation.enable_benchmarks(true);

        for (i, &keygen_i) in (1..).zip(s_l) {
            simulation.add_party(
                OfflineStage::new(
                    i,
                    s_l.to_vec(),
                    local_keys[usize::from(keygen_i - 1)].clone(),
                )
                .unwrap(),
            );
        }

        let stages = simulation.run().unwrap();

        println!("Benchmark results:");
        println!("{:#?}", simulation.benchmark_results().unwrap());

        stages
    }

    fn simulate_signing(offline: Vec<CompletedOfflineStage>, message: &[u8]) {
        let message = Sha256::new()
            .chain_bigint(&BigInt::from_bytes(message))
            .result_bigint();
        let pk = offline[0].public_key().clone();

        let parties = offline
            .iter()
            .map(|o| SignManual::new(message.clone(), o.clone()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (parties, local_sigs): (Vec<_>, Vec<_>) = parties.into_iter().unzip();
        // parties.remove(0).complete(&local_sigs[1..]).unwrap();
        let local_sigs_except = |i: usize| {
            let mut v = vec![];
            v.extend_from_slice(&local_sigs[..i]);
            if i + 1 < local_sigs.len() {
                v.extend_from_slice(&local_sigs[i + 1..]);
            }
            v
        };

        assert!(parties
            .into_iter()
            .enumerate()
            .map(|(i, p)| p.complete(&local_sigs_except(i)).unwrap())
            .all(|signature| verify(&signature, &pk, &message).is_ok()));
    }

    #[test]
    fn simulate_offline_stage_t1_n2_s2() {
        let local_keys = simulate_keygen(1, 2);
        simulate_offline_stage(local_keys, &[1, 2]);
    }

    #[test]
    fn simulate_offline_stage_t1_n3_s2() {
        let local_keys = simulate_keygen(1, 3);
        simulate_offline_stage(local_keys, &[1, 3]);
    }

    #[test]
    fn simulate_offline_stage_t2_n3_s3() {
        let local_keys = simulate_keygen(2, 3);
        simulate_offline_stage(local_keys, &[1, 2, 3]);
    }

    #[test]
    fn simulate_signing_t1_n2_s2() {
        let local_keys = simulate_keygen(1, 2);
        let offline_stage = simulate_offline_stage(local_keys, &[1, 2]);
        simulate_signing(offline_stage, b"ZenGo")
    }

    #[test]
    fn simulate_signing_t1_n3_s2() {
        let local_keys = simulate_keygen(1, 3);
        let offline_stage = simulate_offline_stage(local_keys.clone(), &[1, 2]);
        simulate_signing(offline_stage, b"ZenGo");
        let offline_stage = simulate_offline_stage(local_keys.clone(), &[1, 3]);
        simulate_signing(offline_stage, b"ZenGo");
        let offline_stage = simulate_offline_stage(local_keys, &[2, 3]);
        simulate_signing(offline_stage, b"ZenGo");
    }

    #[test]
    fn simulate_signing_t2_n3_s3() {
        let local_keys = simulate_keygen(2, 3);
        let offline_stage = simulate_offline_stage(local_keys, &[1, 2, 3]);
        simulate_signing(offline_stage, b"ZenGo")
    }
}
