pub trait RoundBlame {
    /// Retrieves a list of uncorporative parties
    ///
    /// Returns a numbers of messages yet to recieve and list of parties to send messages for the current round
    fn round_blame(&self) -> (u16, Vec<u16>);
}

pub trait MessageRoundID: Clone {
    /// Returns the round id of the message
    fn round_id(&self) -> u16;
}
