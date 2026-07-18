use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: checks imbalance_threshold before proportional deposit
    pub fn restore(amounts: [u128; 2]) {
        require(!is_imbalanced(amounts));
        add_liquidity(amounts);
    }
}
fn is_imbalanced(_a: [u128; 2]) -> bool { false }
fn add_liquidity(_a: [u128; 2]) {}
fn require(_: bool) {}
