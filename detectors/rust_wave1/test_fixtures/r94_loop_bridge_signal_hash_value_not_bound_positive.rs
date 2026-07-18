use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Signal;
#[contractimpl]
impl Signal {
    // BUG: hash omits value/amount/fee fields — only header
    pub fn send_signal(from: u64, to: u64, value: u128) -> u128 {
        let h = keccak256(&(from, to));
        store(h);
        value
    }
}
fn keccak256(_x: &(u64, u64)) -> u128 { 0 }
fn store(_h: u128) {}
