use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn _receive_message(_src_chain: u16, _src_addr: Address, _nonce: u64, _payload: &[u8]) {}
fn load_failed_payload(_nonce: u64) -> Vec<u8> { Vec::new() }
fn is_trusted_remote(_src_chain: u16, _src_addr: Address) -> bool { true }
#[contract]
pub struct CrossChainBridge;
#[contractimpl]
impl CrossChainBridge {
    // SAFE: re-verifies is_trusted_remote source before re-invoking _receive_message
    pub fn retry_message(src_chain: u16, src_addr: Address, nonce: u64) {
        assert!(is_trusted_remote(src_chain, src_addr), "untrusted remote");
        let payload = load_failed_payload(nonce);
        _receive_message(src_chain, src_addr, nonce, &payload);
    }
}
