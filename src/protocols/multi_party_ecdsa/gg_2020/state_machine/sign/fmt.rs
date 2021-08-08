use std::fmt;

use round_based::containers::{BroadcastMsgsStore, MessageStore, P2PMsgsStore};

impl fmt::Debug for super::OfflineStage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        OfflineStageProgress::from(self).fmt(f)
    }
}

#[derive(Debug)]
pub struct OfflineStageProgress {
    round: OfflineR,

    decommit_round: DecommitR,

    round1_msgs: ReceivedMessages,
    round2_msgs: (ReceivedMessages, ReceivedMessages),
    round3_msgs: (ReceivedMessages, ReceivedMessages),
    round4_msgs: (ReceivedMessages, ReceivedMessages, ReceivedMessages),
    decom_round_msgs: ReceivedMessages,

    msgs_queue: OutgoingMessages,
}

impl From<&super::OfflineStage> for OfflineStageProgress {
    fn from(state: &super::OfflineStage) -> Self {
        Self {
            round: match &state.round {
                super::OfflineR::R0(_) => OfflineR::R0,
                super::OfflineR::R1(_) => OfflineR::R1,
                super::OfflineR::R2(_) => OfflineR::R2,
                super::OfflineR::CR2(_) => OfflineR::CR2,
                super::OfflineR::R3(_) => OfflineR::R3,
                super::OfflineR::R4(_) => OfflineR::R4,
                super::OfflineR::Finished(_) => OfflineR::Finished,
                super::OfflineR::Gone => OfflineR::Gone,
            },

            decommit_round: match &state.decommit_round {
                super::DecommitR::NotStarted => DecommitR::NotStarted,
                super::DecommitR::R0(_) => DecommitR::R0,
                super::DecommitR::Finished(_) => DecommitR::Finished,
                super::DecommitR::Gone => DecommitR::Gone,
            },

            round1_msgs: ReceivedMessages::from_broadcast(state.msgs1.as_ref()),
            round2_msgs: (
                ReceivedMessages::from_broadcast(state.msgs2.as_ref().map(|s| &s.0)),
                ReceivedMessages::from_p2p(state.msgs2.as_ref().map(|s| &s.1)),
            ),
            round3_msgs: (
                ReceivedMessages::from_broadcast(state.msgs3.as_ref().map(|s| &s.0)),
                ReceivedMessages::from_broadcast(state.msgs3.as_ref().map(|s| &s.1)),
            ),
            round4_msgs: (
                ReceivedMessages::from_broadcast(state.msgs4.as_ref().map(|s| &s.0)),
                ReceivedMessages::from_broadcast(state.msgs4.as_ref().map(|s| &s.1)),
                ReceivedMessages::from_broadcast(state.msgs4.as_ref().map(|s| &s.2)),
             ),
            decom_round_msgs: ReceivedMessages::from_broadcast(state.msgs_com.as_ref()),

            msgs_queue: OutgoingMessages {
                len: state.msgs_queue.0.len(),
            },
        }
    }
}

#[derive(Debug)]
pub enum OfflineR {
    R0,
    R1,
    R2,
    CR2,
    R3,
    R4,
    Finished,
    Gone,
}

#[derive(Debug)]
pub enum DecommitR {
    NotStarted,
    R0,
    Finished,
    Gone,
}

pub enum ContainerType {
    P2P,
    Broadcast,
}

pub struct ReceivedMessages(Option<MessagesContainer>);

pub struct MessagesContainer {
    ty: ContainerType,
    total: usize,
    waiting_for: Vec<u16>,
}

impl ReceivedMessages {
    fn from_broadcast<T>(store: Option<&BroadcastMsgsStore<T>>) -> Self {
        match store {
            Some(store) => ReceivedMessages(Some(MessagesContainer {
                ty: ContainerType::Broadcast,
                total: store.messages_total(),
                waiting_for: store.blame().1,
            })),
            None => ReceivedMessages(None),
        }
    }
    fn from_p2p<T>(store: Option<&P2PMsgsStore<T>>) -> Self {
        match store {
            Some(store) => ReceivedMessages(Some(MessagesContainer {
                ty: ContainerType::P2P,
                total: store.messages_total(),
                waiting_for: store.blame().1,
            })),
            None => ReceivedMessages(None),
        }
    }
}

impl fmt::Debug for ReceivedMessages {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            Some(container) => {
                let ty = match container.ty {
                    ContainerType::Broadcast => "bc",
                    ContainerType::P2P => "p2p",
                };
                write!(
                    f,
                    "[{} {}/{}]",
                    ty,
                    container.total - container.waiting_for.len(),
                    container.total
                )
            }
            None => write!(f, "[gone]"),
        }
    }
}

#[derive(Debug)]
pub struct OutgoingMessages {
    len: usize,
}
