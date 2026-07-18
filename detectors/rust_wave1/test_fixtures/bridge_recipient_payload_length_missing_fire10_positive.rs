use std::collections::HashSet;

pub struct BridgeState {
    pub consumed_messages: HashSet<Vec<u8>>,
    pub burned_supply: u128,
}

pub fn mint_to(_recipient: [u8; 20], _amount: u128) {}

impl BridgeState {
    pub fn process_bridge_message(
        &mut self,
        payload: &[u8],
        replay_key: Vec<u8>,
        amount: u128,
    ) -> Result<(), &'static str> {
        if payload.is_empty() {
            return Err("empty message");
        }

        let copy_len = payload.len().min(20);
        let mut recipient = [0u8; 20];
        recipient[..copy_len].copy_from_slice(&payload[..copy_len]);

        self.burned_supply += amount;
        self.consumed_messages.insert(replay_key);
        mint_to(recipient, amount);
        Ok(())
    }
}
