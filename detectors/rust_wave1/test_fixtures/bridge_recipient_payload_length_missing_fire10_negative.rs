use std::collections::HashSet;

pub struct BridgeState {
    pub consumed_messages: HashSet<Vec<u8>>,
    pub expected_recipient_domain: u32,
    pub released: u128,
}

pub fn release_tokens_to(_recipient: [u8; 20], _amount: u128) {}

impl BridgeState {
    pub fn process_bridge_message(
        &mut self,
        payload: &[u8],
        replay_key: Vec<u8>,
        amount: u128,
        recipient_domain: u32,
    ) -> Result<(), &'static str> {
        if payload.len() != 20 {
            return Err("recipient must be exactly 20 bytes");
        }
        if recipient_domain != self.expected_recipient_domain {
            return Err("recipient domain mismatch");
        }

        let mut recipient = [0u8; 20];
        recipient.copy_from_slice(payload);

        self.consumed_messages.insert(replay_key);
        self.released += amount;
        release_tokens_to(recipient, amount);
        Ok(())
    }
}
