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
use gg20::party_i::{LocalSignature, SignBroadcastPhase1, SignDecommitPhase1, SignatureRecid};
use gg20::state_machine::keygen::LocalKey;

mod fmt;
mod rounds;

use curv::BigInt;
use rounds::*;
pub use rounds::{CompletedOfflineStage, Error as ProceedError};

/// Offline Stage of GG20 signing
///
/// Successfully carried out Offline Stage will produce [CompletedOfflineStage] that can
/// be used for one-round signing multiple times.
pub struct OfflineStage {
    round: OfflineR,
    decommit_round: DecommitR,

    msgs1: Option<Store<BroadcastMsgs<MessageA>>>,
    msgs2: Option<(Store<BroadcastMsgs<GWI>>, Store<P2PMsgs<(GammaI, WI)>>)>,
    msgs3: Option<(
        Store<BroadcastMsgs<SignDecommitPhase1>>,
        Store<BroadcastMsgs<DeltaI>>,
    )>,
    msgs4: Option<Store<BroadcastMsgs<RDash>>>,
    msgs_com: Option<Store<BroadcastMsgs<SignBroadcastPhase1>>>,

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
    pub fn new(i: u16, s_l: Vec<u16>, local_key: LocalKey) -> Result<Self> {
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
            s_l_sorted.sort();
            let mut s_l_sorted_deduped = s_l_sorted.clone();
            s_l_sorted_deduped.dedup();

            if s_l_sorted != s_l_sorted_deduped {
                return Err(Error::InvalidSl);
            }
        }

        let n = u16::try_from(s_l.len()).map_err(|_| Error::TooManyParties { n: s_l.len() })?;

        Ok(Self {
            round: OfflineR::R0(Round0 { i, s_l, local_key }),
            decommit_round: DecommitR::NotStarted,

            msgs1: Some(Round1::expects_messages(i, n)),
            msgs2: Some(Round2::expects_messages(i, n)),
            msgs3: Some(Round3::expects_messages(i, n)),
            msgs4: Some(Round4::expects_messages(i, n)),
            msgs_com: Some(DecommitRound::expects_messages(i, n)),

            msgs_queue: MsgQueue(vec![]),

            party_i: i,
            party_n: n,
        })
    }

    fn proceed_state(&mut self, may_block: bool) -> Result<()> {
        self.proceed_round(may_block)?;
        self.proceed_decommit_round(may_block)
    }

    fn proceed_round(&mut self, may_block: bool) -> Result<()> {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self
            .msgs2
            .as_ref()
            .map(|(s1, s2)| s1.wants_more() || s2.wants_more())
            .unwrap_or(false);
        let store3_wants_more = self
            .msgs3
            .as_ref()
            .map(|(s1, s2)| s1.wants_more() || s2.wants_more())
            .unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        let next_state: OfflineR;
        let try_again: bool = match replace(&mut self.round, OfflineR::Gone) {
            OfflineR::R0(round) if !round.is_expensive() || may_block => {
                if !matches!(self.decommit_round, DecommitR::NotStarted) {
                    return Err(InternalError::DecommitRoundWasntInInitialState.into());
                }
                let (next_s, next_d) = round
                    .proceed(&mut self.msgs_queue)
                    .map_err(Error::ProceedRound)?;
                next_state = OfflineR::R1(next_s);
                self.decommit_round = DecommitR::R0(next_d);
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
                let (store1, store2) = self.msgs2.take().ok_or(InternalError::StoreGone)?;
                let msgs1 = store1
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                let msgs2 = store2
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs1, msgs2, &mut self.msgs_queue)
                    .map(OfflineR::CR2)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ OfflineR::R2(_) => {
                next_state = s;
                false
            }
            OfflineR::CR2(completed_round) => match self.decommit_round.steal_results() {
                Some(result) => {
                    next_state = OfflineR::R3(Round3::new(completed_round, result));
                    true
                }
                None => {
                    next_state = OfflineR::CR2(completed_round);
                    false
                }
            },
            OfflineR::R3(round) if !store3_wants_more && (!round.is_expensive() || may_block) => {
                let (store1, store2) = self.msgs3.take().ok_or(InternalError::StoreGone)?;
                let msgs1 = store1
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                let msgs2 = store2
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs1, msgs2, &mut self.msgs_queue)
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
                    .proceed(msgs)
                    .map(OfflineR::Finished)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ OfflineR::R4(_) => {
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

    fn proceed_decommit_round(&mut self, may_block: bool) -> Result<()> {
        let store_com_wants_more = self
            .msgs_com
            .as_ref()
            .map(|s| s.wants_more())
            .unwrap_or(false);

        let next_state: DecommitR;
        let finished: bool = match replace(&mut self.decommit_round, DecommitR::Gone) {
            s @ DecommitR::NotStarted => {
                next_state = s;
                false
            }
            DecommitR::R0(round)
                if !store_com_wants_more && (!round.is_expensive() || may_block) =>
            {
                let store = self.msgs_com.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(DecommitR::Finished)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ DecommitR::R0(_) => {
                next_state = s;
                false
            }
            s @ DecommitR::Finished(_) => {
                next_state = s;
                true
            }
            s @ DecommitR::Gone => {
                next_state = s;
                false
            }
        };
        self.decommit_round = next_state;

        if finished {
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
            OfflineProtocolMessage(OfflineM::M2A(m)) => {
                let (store, _) = self
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
            OfflineProtocolMessage(OfflineM::M2B(m)) => {
                let (_, store) = self
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
            OfflineProtocolMessage(OfflineM::M3A(m)) => {
                let (store, _) = self
                    .msgs3
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 3,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M3B(m)) => {
                let (_, store) = self
                    .msgs3
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 3,
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
                        msg_round: 4,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::MD(m)) => {
                let store = self
                    .msgs_com
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 10,
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
        self.proceed_state(false)
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue.0
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self
            .msgs2
            .as_ref()
            .map(|(s1, s2)| s1.wants_more() || s2.wants_more())
            .unwrap_or(false);
        let store3_wants_more = self
            .msgs3
            .as_ref()
            .map(|(s1, s2)| s1.wants_more() || s2.wants_more())
            .unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store_com_wants_more = self
            .msgs_com
            .as_ref()
            .map(|s| s.wants_more())
            .unwrap_or(false);

        let proceed_round = match &self.round {
            OfflineR::R0(_) => true,
            OfflineR::R1(_) => !store1_wants_more,
            OfflineR::R2(_) => !store2_wants_more,
            OfflineR::CR2(_) => matches!(&self.decommit_round, DecommitR::Finished(_)),
            OfflineR::R3(_) => !store3_wants_more,
            OfflineR::R4(_) => !store4_wants_more,
            OfflineR::Finished(_) | OfflineR::Gone => false,
        };

        let proceed_decommit_round = match &self.decommit_round {
            DecommitR::NotStarted => false,
            DecommitR::R0(_) => !store_com_wants_more,
            DecommitR::Finished(_) | DecommitR::Gone => false,
        };

        proceed_round || proceed_decommit_round
    }

    fn proceed(&mut self) -> Result<(), Self::Err> {
        self.proceed_state(true)
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
            OfflineR::CR2(_) => 2,
            OfflineR::R3(_) => 3,
            OfflineR::R4(_) => 4,
            OfflineR::Finished(_) | OfflineR::Gone => 5,
        }
    }

    fn total_rounds(&self) -> Option<u16> {
        Some(4)
    }

    fn party_ind(&self) -> u16 {
        self.party_i
    }

    fn parties(&self) -> u16 {
        self.party_n
    }
}

enum OfflineR {
    R0(Round0),
    R1(Round1),
    R2(Round2),
    CR2(CompletedRound2),
    R3(Round3),
    R4(Round4),
    Finished(CompletedOfflineStage),
    Gone,
}

enum DecommitR {
    NotStarted,
    R0(DecommitRound),
    Finished(Commitments),
    Gone,
}

impl DecommitR {
    pub fn steal_results(&mut self) -> Option<Commitments> {
        match replace(self, DecommitR::Gone) {
            DecommitR::Finished(r) => Some(r),
            s => {
                *self = s;
                None
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OfflineProtocolMessage(OfflineM);

#[derive(Serialize, Deserialize, Debug, Clone)]
enum OfflineM {
    M1(MessageA),
    M2A(GWI),
    M2B((GammaI, WI)),
    M3A(SignDecommitPhase1),
    M3B(DeltaI),
    M4(RDash),

    MD(SignBroadcastPhase1),
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
    M1 MessageA,
    M2A GWI,
    M2B (GammaI, WI),
    M3A SignDecommitPhase1,
    M3B DeltaI,
    M4 RDash,
    MD SignBroadcastPhase1,
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
/// #     state_machine::sign::{CompletedOfflineStage, SignManual},
/// #     party_i::{LocalSignature, verify},
/// # };
/// # use curv::arithmetic::{BigInt, Converter};
/// # type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
/// # fn broadcast(msg: LocalSignature) -> Result<()> { panic!() }
/// # fn wait_messages() -> Result<Vec<LocalSignature>> { panic!() }
/// # fn main() -> Result<()> {
/// # let completed_offline_stage: CompletedOfflineStage = panic!();
/// let data = BigInt::from_bytes(b"a message");
///
/// // Sign a message locally
/// let (sign, msg) = SignManual::new(data.clone(), completed_offline_stage)?;
/// // Broadcast local signature
/// broadcast(msg)?;
/// // Collect local signatures from all the parties
/// let sigs: Vec<LocalSignature> = wait_messages()?;
/// // Complete signing
/// let signature = sign.complete(sigs)?;
/// // Verify that signature matches joint public key
/// assert!(verify(&signature, completed_offline_stage.public_key(), &data).is_ok());
/// # Ok(())
/// # }
/// ```
pub struct SignManual {
    state: Round6,
}

impl SignManual {
    pub fn new(
        message_bn: BigInt,
        completed_offline_stage: CompletedOfflineStage,
    ) -> Result<(Self, LocalSignature), SignError> {
        Round5::new(message_bn, completed_offline_stage)
            .proceed_manual()
            .map(|(state, m)| (Self { state }, m))
            .map_err(SignError::LocalSigning)
    }

    pub fn complete(self, sigs: Vec<LocalSignature>) -> Result<SignatureRecid, SignError> {
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
    use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
    use curv::cryptographic_primitives::hashing::traits::Hash;
    use round_based::dev::Simulation;

    use super::*;
    use gg20::party_i::verify;
    use gg20::state_machine::keygen::test::simulate_keygen;

    fn simulate_offline_stage(
        local_keys: Vec<LocalKey>,
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
        let message = HSha256::create_hash(&[&BigInt::from_bytes(message)]);
        let pk = offline[0].public_key().clone();

        let parties = offline
            .iter()
            .map(|o| SignManual::new(message.clone(), o.clone()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (parties, local_sigs): (Vec<_>, Vec<_>) = parties.into_iter().unzip();

        assert!(parties
            .into_iter()
            .map(|p| p.complete(local_sigs.clone()).unwrap())
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
        let offline_stage = simulate_offline_stage(local_keys.clone(), &[2, 3]);
        simulate_signing(offline_stage, b"ZenGo");
    }

    #[test]
    fn simulate_signing_t2_n3_s3() {
        let local_keys = simulate_keygen(2, 3);
        let offline_stage = simulate_offline_stage(local_keys, &[1, 2, 3]);
        simulate_signing(offline_stage, b"ZenGo")
    }
}
