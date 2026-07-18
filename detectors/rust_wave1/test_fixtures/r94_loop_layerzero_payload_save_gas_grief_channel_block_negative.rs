use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;
type Address = [u8; 20];
pub struct Storage { failed_message_hashes: HashMap<(u16, Address, u64), [u8; 32]> }
fn get_storage() -> Storage { Storage { failed_message_hashes: HashMap::new() } }
fn save_storage(_s: &Storage) {}
fn keccak256(_: &[u8]) -> [u8; 32] { [0; 32] }
#[contract]
pub struct LzReceiver;
#[contractimpl]
impl LzReceiver {
    // SAFE: stores a 32-byte keccak(payload) digest instead of raw payload
    pub fn lz_receive(src_chain: u16, src_addr: Address, nonce: u64, payload: Vec<u8>) {
        let mut storage = get_storage();
        let key = (src_chain, src_addr, nonce);
        let payload_hash = keccak256(&payload);
        storage.failed_message_hashes.insert(key, payload_hash);
        save_storage(&storage);
    }
}
