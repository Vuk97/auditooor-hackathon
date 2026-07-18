use soroban_sdk::{contract, contractimpl};

pub struct Origin { nonce: u64 }
fn process_message(_n: u64) {}
#[contract]
pub struct X;
#[contractimpl]
impl X {
    pub fn lz_receive(origin: Origin, payload: Vec<u8>) {
        let nonce = origin.nonce;
        process_message(nonce);
        let _ = payload;
    }
}
