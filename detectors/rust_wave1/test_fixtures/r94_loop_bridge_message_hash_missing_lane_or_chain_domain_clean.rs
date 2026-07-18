use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct BridgeInbox;

#[contractimpl]
impl BridgeInbox {
    pub fn bridge_message_digest(
        nonce: u64,
        payload_hash: [u8; 32],
        lane_id: u32,
        source_chain: u64,
    ) -> [u8; 32] {
        sha256(&(nonce, payload_hash, lane_id, source_chain))
    }
}

fn sha256(_parts: &(u64, [u8; 32], u32, u64)) -> [u8; 32] {
    [0u8; 32]
}
