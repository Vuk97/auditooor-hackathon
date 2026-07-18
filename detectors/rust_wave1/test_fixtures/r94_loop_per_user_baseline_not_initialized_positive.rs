use soroban_sdk::{contract, contractimpl};
pub struct Position { pub amount: u128, pub amount_claimed: u128 }
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: new position created, amount_claimable_per_share in scope, baseline not init
    pub fn deposit(positions: &mut std::collections::HashMap<u64, Position>, user: u64, amount: u128, amount_claimable_per_share: u128) {
        let new_position = Position { amount, amount_claimed: 0 };
        positions.insert(user, new_position);
    }
}
