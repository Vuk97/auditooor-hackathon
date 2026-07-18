use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct OApp;
#[contractimpl]
impl OApp {
    // BUG: no src-chain-id / channel-id / peer check
    pub fn lz_receive(src_chain_id: u32, sender: [u8; 32], payload: Vec<u8>) {
        handle_payload(payload);
    }
}
fn handle_payload(_p: Vec<u8>) {}
