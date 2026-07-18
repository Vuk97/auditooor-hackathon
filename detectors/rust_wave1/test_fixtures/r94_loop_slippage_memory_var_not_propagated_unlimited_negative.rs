use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct DcaSwap;

#[contractimpl]
impl DcaSwap {
    pub fn swap(amount_in: u128) {
        let mut slippage: u128;
        slippage = amount_in / 100;
        let _ = slippage;
    }
}
