use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Library;
#[contractimpl]
impl Library {
    // BUG: triple-multiply without mulDiv, intermediate can overflow u128
    pub fn pnl(position: u128, price: u128, fee_bps: u128) -> u128 {
        position * price * fee_bps / 1_000_000_000_000_000_000u128
    }
}
