use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct BridgeInbox;

#[contractimpl]
impl BridgeInbox {
    pub fn bridge_message_digest(
        nonce: u64,
        payload_hash: [u8; 32],
        destination_domain: u64,
        source_chain: u64,
    ) -> [u8; 32] {
        let _ = destination_domain;
        let _ = source_chain;
        sha256(&(nonce, payload_hash))
    }
}

fn sha256(_parts: &(u64, [u8; 32])) -> [u8; 32] {
    [0u8; 32]
}
