use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeSignal;
#[contractimpl]
impl SafeSignal {
    // OK: hash includes value and fee in the encoded tuple
    pub fn send_signal(from: u64, to: u64, value: u128, fee: u128) -> u128 {
        let h = keccak256(&(from, to, value, fee));
        store(h);
        value
    }
}
fn keccak256(_x: &(u64, u64, u128, u128)) -> u128 { 0 }
fn store(_h: u128) {}
