use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Engine;
#[contractimpl]
impl Engine {
    // BUG: pays liquidator reward without ensuring caller != position.owner
    pub fn liquidate(position_owner: u64, caller: u64, bounty: u128) -> u128 {
        let _ = position_owner;
        let liquidation_reward = bounty;
        token_transfer(caller, liquidation_reward);
        liquidation_reward
    }
}
fn token_transfer(_to: u64, _a: u128) {}
