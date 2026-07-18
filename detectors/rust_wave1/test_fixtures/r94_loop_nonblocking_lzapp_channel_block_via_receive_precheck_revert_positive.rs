use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn process_onft(_nonce: u64, _payload: &[u8]) {}
fn token_exists(_token_id: u64) -> bool { false }
#[contract]
pub struct HoneyJarONFT;
#[contractimpl]
impl HoneyJarONFT {
    // BUG: require! pre-check before any try-catch; revert bricks LZ channel
    pub fn lz_receive(src_chain: u16, src_addr: Address, nonce: u64, payload: Vec<u8>) {
        require!(token_exists(nonce), "token must not yet exist");
        process_onft(nonce, &payload);
    }
}
#[macro_export]
macro_rules! require { ($cond:expr, $msg:expr) => { if !$cond { panic!("{}", $msg); } }; }
