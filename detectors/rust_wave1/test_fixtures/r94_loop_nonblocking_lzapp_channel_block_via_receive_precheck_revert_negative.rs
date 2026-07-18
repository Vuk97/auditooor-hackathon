use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn process_onft(_nonce: u64, _payload: &[u8]) -> Result<(), &'static str> { Ok(()) }
fn store_failed(_nonce: u64, _err: &str) {}
#[contract]
pub struct HoneyJarONFT;
#[contractimpl]
impl HoneyJarONFT {
    // SAFE: wraps work inside try-match-Result, failures stored instead of reverting
    pub fn lz_receive(src_chain: u16, src_addr: Address, nonce: u64, payload: Vec<u8>) {
        match process_onft(nonce, &payload) {
            Ok(()) => {},
            Err(e) => store_failed(nonce, e),
        }
    }
}
