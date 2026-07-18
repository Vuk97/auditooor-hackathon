use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeEngine;
#[contractimpl]
impl SafeEngine {
    // OK: guards caller != position.owner before paying reward
    pub fn liquidate(position_owner: u64, caller: u64, bounty: u128) -> u128 {
        require(caller != position_owner);
        let liquidation_reward = bounty;
        token_transfer(caller, liquidation_reward);
        liquidation_reward
    }
}
fn require(_c: bool) {}
fn token_transfer(_to: u64, _a: u128) {}
