use soroban_sdk::{contract, contractimpl};

fn self_balance() -> u128 {
    1000
}

fn transfer_native(_to: [u8; 20], _a: u128) {}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn sell_to_liquidity_provider(user: [u8; 20], amount: u128) {
        let refund = self_balance() - amount;
        transfer_native(user, refund);
    }
}
