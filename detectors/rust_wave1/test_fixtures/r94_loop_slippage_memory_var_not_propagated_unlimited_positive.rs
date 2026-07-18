use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct DcaSwap;

#[contractimpl]
impl DcaSwap {
    pub fn swap(amount_in: u128) {
        let slippage: u128;  // never assigned
        let _ = amount_in;
        let _ = slippage;
    }
}
