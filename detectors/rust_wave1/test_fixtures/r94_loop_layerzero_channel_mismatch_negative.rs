use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeOApp;
#[contractimpl]
impl SafeOApp {
    // OK: src_chain_id + peer validated
    pub fn lz_receive(src_chain_id: u32, sender: [u8; 32], payload: Vec<u8>) {
        require(src_chain_id == expected_src_chain());
        require(sender == trusted_remote(src_chain_id));
        handle_payload(payload);
    }
}
fn require(_: bool) {}
fn expected_src_chain() -> u32 { 1 }
fn trusted_remote(_s: u32) -> [u8; 32] { [0; 32] }
fn handle_payload(_p: Vec<u8>) {}
