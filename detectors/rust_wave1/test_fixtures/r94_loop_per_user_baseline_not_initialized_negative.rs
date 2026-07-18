use soroban_sdk::{contract, contractimpl};
pub struct Position { pub amount: u128, pub amount_claimed: u128 }
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: amount_claimed initialized to current accumulator
    pub fn deposit(positions: &mut std::collections::HashMap<u64, Position>, user: u64, amount: u128, amount_claimable_per_share: u128) {
        let new_position = Position { amount, amount_claimed: amount_claimable_per_share };
        positions.insert(user, new_position);
    }
}
