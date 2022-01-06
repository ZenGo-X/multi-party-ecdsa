//! High-level keygen protocol implementation

use std::fmt;
use std::mem::replace;
use std::time::Duration;

use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};
use round_based::containers::{
    push::{Push, PushExt},
    *,
};
use round_based::{IsCritical, Msg, StateMachine};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::protocols::multi_party_ecdsa::gg_2020;

mod rounds;

use private::InternalError;
pub use rounds::{LocalKey, ProceedError};
use rounds::{Round0, Round1, Round2, Round3, Round4};

/// Keygen protocol state machine
///
/// Successfully completed keygen protocol produces [LocalKey] that can be used in further
/// [signing](super::sign) protocol.
pub struct Keygen {
    round: R,

    msgs1: Option<Store<BroadcastMsgs<gg_2020::party_i::KeyGenBroadcastMessage1>>>,
    msgs2: Option<Store<BroadcastMsgs<gg_2020::party_i::KeyGenDecommitMessage1>>>,
    msgs3: Option<Store<P2PMsgs<(VerifiableSS<Secp256k1>, Scalar<Secp256k1>)>>>,
    msgs4: Option<Store<BroadcastMsgs<DLogProof<Secp256k1, Sha256>>>>,

    msgs_queue: Vec<Msg<ProtocolMessage>>,

    party_i: u16,
    party_n: u16,
}

impl Keygen {
    /// Constructs a party of keygen protocol
    ///
    /// Takes party index `i` (in range `[1; n]`), threshold value `t`, and total number of
    /// parties `n`. Party index identifies this party in the protocol, so it must be guaranteed
    /// to be unique.
    ///
    /// Returns error if:
    /// * `n` is less than 2, returns [Error::TooFewParties]
    /// * `t` is not in range `[1; n-1]`, returns [Error::InvalidThreshold]
    /// * `i` is not in range `[1; n]`, returns [Error::InvalidPartyIndex]
    pub fn new(i: u16, t: u16, n: u16) -> Result<Self> {
        if n < 2 {
            return Err(Error::TooFewParties);
        }
        if t == 0 || t >= n {
            return Err(Error::InvalidThreshold);
        }
        if i == 0 || i > n {
            return Err(Error::InvalidPartyIndex);
        }
        let mut state = Self {
            round: R::Round0(Round0 { party_i: i, t, n }),

            msgs1: Some(Round1::expects_messages(i, n)),
            msgs2: Some(Round2::expects_messages(i, n)),
            msgs3: Some(Round3::expects_messages(i, n)),
            msgs4: Some(Round4::expects_messages(i, n)),

            msgs_queue: vec![],

            party_i: i,
            party_n: n,
        };

        state.proceed_round(false)?;
        Ok(state)
    }

    fn gmap_queue<'a, T, F>(&'a mut self, mut f: F) -> impl Push<Msg<T>> + 'a
    where
        F: FnMut(T) -> M + 'a,
    {
        (&mut self.msgs_queue).gmap(move |m: Msg<T>| m.map_body(|m| ProtocolMessage(f(m))))
    }

    /// Proceeds round state if it received enough messages and if it's cheap to compute or
    /// `may_block == true`
    fn proceed_round(&mut self, may_block: bool) -> Result<()> {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        let next_state: R;
        let try_again: bool = match replace(&mut self.round, R::Gone) {
            R::Round0(round) if !round.is_expensive() || may_block => {
                next_state = round
                    .proceed(self.gmap_queue(M::Round1))
                    .map(R::Round1)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round0(_) => {
                next_state = s;
                false
            }
            R::Round1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs1.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs, self.gmap_queue(M::Round2))
                    .map(R::Round2)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round1(_) => {
                next_state = s;
                false
            }
            R::Round2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs2.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs, self.gmap_queue(M::Round3))
                    .map(R::Round3)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round2(_) => {
                next_state = s;
                false
            }
            R::Round3(round) if !store3_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs3.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs, self.gmap_queue(M::Round4))
                    .map(R::Round4)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round3(_) => {
                next_state = s;
                false
            }
            R::Round4(round) if !store4_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs4.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveRoundMessages)?;
                next_state = round
                    .proceed(msgs)
                    .map(R::Final)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ R::Round4(_) => {
                next_state = s;
                false
            }
            s @ R::Final(_) | s @ R::Gone => {
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

impl StateMachine for Keygen {
    type MessageBody = ProtocolMessage;
    type Err = Error;
    type Output = LocalKey<Secp256k1>;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<()> {
        let current_round = self.current_round();

        match msg.body {
            ProtocolMessage(M::Round1(m)) => {
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
                self.proceed_round(false)
            }
            ProtocolMessage(M::Round2(m)) => {
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
                self.proceed_round(false)
            }
            ProtocolMessage(M::Round3(m)) => {
                let store = self
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
                self.proceed_round(false)
            }
            ProtocolMessage(M::Round4(m)) => {
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
                self.proceed_round(false)
            }
        }
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);

        match &self.round {
            R::Round0(_) => true,
            R::Round1(_) => !store1_wants_more,
            R::Round2(_) => !store2_wants_more,
            R::Round3(_) => !store3_wants_more,
            R::Round4(_) => !store4_wants_more,
            R::Final(_) | R::Gone => false,
        }
    }

    fn proceed(&mut self) -> Result<()> {
        self.proceed_round(true)
    }

    fn round_timeout(&self) -> Option<Duration> {
        None
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        panic!("no timeout was set")
    }

    fn is_finished(&self) -> bool {
        matches!(self.round, R::Final(_))
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output>> {
        match self.round {
            R::Final(_) => (),
            R::Gone => return Some(Err(Error::DoublePickOutput)),
            _ => return None,
        }

        match replace(&mut self.round, R::Gone) {
            R::Final(result) => Some(Ok(result)),
            _ => unreachable!("guaranteed by match expression above"),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            R::Round0(_) => 0,
            R::Round1(_) => 1,
            R::Round2(_) => 2,
            R::Round3(_) => 3,
            R::Round4(_) => 4,
            R::Final(_) | R::Gone => 5,
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

impl super::traits::RoundBlame for Keygen {
    /// Returns number of unwilling parties and a vector of their party indexes.
    fn round_blame(&self) -> (u16, Vec<u16>) {
        let store1_blame = self.msgs1.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store2_blame = self.msgs2.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store3_blame = self.msgs3.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store4_blame = self.msgs4.as_ref().map(|s| s.blame()).unwrap_or_default();

        let default = (0, vec![]);
        match &self.round {
            R::Round0(_) => default,
            R::Round1(_) => store1_blame,
            R::Round2(_) => store2_blame,
            R::Round3(_) => store3_blame,
            R::Round4(_) => store4_blame,
            R::Final(_) | R::Gone => default,
        }
    }
}

impl fmt::Debug for Keygen {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let current_round = match &self.round {
            R::Round0(_) => "0",
            R::Round1(_) => "1",
            R::Round2(_) => "2",
            R::Round3(_) => "3",
            R::Round4(_) => "4",
            R::Final(_) => "[Final]",
            R::Gone => "[Gone]",
        };
        let msgs1 = match self.msgs1.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs2 = match self.msgs2.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs3 = match self.msgs3.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        let msgs4 = match self.msgs4.as_ref() {
            Some(msgs) => format!("[{}/{}]", msgs.messages_received(), msgs.messages_total()),
            None => "[None]".into(),
        };
        write!(
            f,
            "{{Keygen at round={} msgs1={} msgs2={} msgs3={} msgs4={} queue=[len={}]}}",
            current_round,
            msgs1,
            msgs2,
            msgs3,
            msgs4,
            self.msgs_queue.len()
        )
    }
}

// Rounds

enum R {
    Round0(Round0),
    Round1(Round1),
    Round2(Round2),
    Round3(Round3),
    Round4(Round4),
    Final(LocalKey<Secp256k1>),
    Gone,
}

// Messages

/// Protocol message which parties send on wire
///
/// Hides actual messages structure so it could be changed without breaking semver policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage(M);

#[derive(Clone, Debug, Serialize, Deserialize)]
enum M {
    Round1(gg_2020::party_i::KeyGenBroadcastMessage1),
    Round2(gg_2020::party_i::KeyGenDecommitMessage1),
    Round3((VerifiableSS<Secp256k1>, Scalar<Secp256k1>)),
    Round4(DLogProof<Secp256k1, Sha256>),
}

// Error

type Result<T> = std::result::Result<T, Error>;

/// Error type of keygen protocol
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Round proceeding resulted in error
    #[error("proceed round: {0}")]
    ProceedRound(#[source] ProceedError),

    /// Too few parties (`n < 2`)
    #[error("at least 2 parties are required for keygen")]
    TooFewParties,
    /// Threshold value `t` is not in range `[1; n-1]`
    #[error("threshold is not in range [1; n-1]")]
    InvalidThreshold,
    /// Party index `i` is not in range `[1; n]`
    #[error("party index is not in range [1; n]")]
    InvalidPartyIndex,

    /// Received message didn't pass pre-validation
    #[error("received message didn't pass pre-validation: {0}")]
    HandleMessage(#[source] StoreErr),
    /// Received message which we didn't expect to receive now (e.g. message from previous round)
    #[error(
        "didn't expect to receive message from round {msg_round} (being at round {current_round})"
    )]
    ReceivedOutOfOrderMessage { current_round: u16, msg_round: u16 },
    /// [Keygen::pick_output] called twice
    #[error("pick_output called twice")]
    DoublePickOutput,

    /// Some internal assertions were failed, which is a bug
    #[doc(hidden)]
    #[error("internal error: {0:?}")]
    InternalError(InternalError),
}

impl IsCritical for Error {
    fn is_critical(&self) -> bool {
        true
    }
}

impl From<InternalError> for Error {
    fn from(err: InternalError) -> Self {
        Self::InternalError(err)
    }
}

mod private {
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum InternalError {
        /// [Messages store](super::MessageStore) reported that it received all messages it wanted to receive,
        /// but refused to return message container
        RetrieveRoundMessages(super::StoreErr),
        #[doc(hidden)]
        StoreGone,
    }
}

#[cfg(test)]
pub mod test {
    use round_based::dev::Simulation;

    use super::*;

    pub fn simulate_keygen(t: u16, n: u16) -> Vec<LocalKey<Secp256k1>> {
        let mut simulation = Simulation::new();
        simulation.enable_benchmarks(true);

        for i in 1..=n {
            simulation.add_party(Keygen::new(i, t, n).unwrap());
        }

        let keys = simulation.run().unwrap();

        println!("Benchmark results:");
        println!("{:#?}", simulation.benchmark_results().unwrap());

        keys
    }

    #[test]
    fn simulate_keygen_t1_n2() {
        simulate_keygen(1, 2);
    }

    #[test]
    fn simulate_keygen_t1_n3() {
        simulate_keygen(1, 3);
    }

    #[test]
    fn simulate_keygen_t2_n3() {
        simulate_keygen(2, 3);
    }
}
