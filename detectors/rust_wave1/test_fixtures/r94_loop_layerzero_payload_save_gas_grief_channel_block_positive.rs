use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;
type Address = [u8; 20];
pub struct Storage { failed_messages: HashMap<(u16, Address, u64), Vec<u8>> }
fn get_storage() -> Storage { Storage { failed_messages: HashMap::new() } }
fn save_storage(_s: &Storage) {}
#[contract]
pub struct LzReceiver;
#[contractimpl]
impl LzReceiver {
    // BUG: persists raw payload into mapping with no length cap / digest
    pub fn lz_receive(src_chain: u16, src_addr: Address, nonce: u64, payload: Vec<u8>) {
        let mut storage = get_storage();
        let key = (src_chain, src_addr, nonce);
        storage.failed_messages.insert(key, payload);
        save_storage(&storage);
    }
}
