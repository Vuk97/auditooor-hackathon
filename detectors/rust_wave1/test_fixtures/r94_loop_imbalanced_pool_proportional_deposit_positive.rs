use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: calls add_liquidity without imbalance check
    pub fn restore(amounts: [u128; 2]) {
        add_liquidity(amounts);
    }
    pub fn reinvest(a: u128, b: u128) {
        add_liquidity([a, b]);
    }
}
fn add_liquidity(_a: [u128; 2]) {}
