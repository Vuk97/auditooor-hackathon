use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn _receive_message(_src_chain: u16, _src_addr: Address, _nonce: u64, _payload: &[u8]) {}
fn load_failed_payload(_nonce: u64) -> Vec<u8> { Vec::new() }
#[contract]
pub struct CrossChainBridge;
#[contractimpl]
impl CrossChainBridge {
    // BUG: retry path bypasses endpoint / trustedRemote check
    pub fn retry_message(src_chain: u16, src_addr: Address, nonce: u64) {
        let payload = load_failed_payload(nonce);
        _receive_message(src_chain, src_addr, nonce, &payload);
    }
}
