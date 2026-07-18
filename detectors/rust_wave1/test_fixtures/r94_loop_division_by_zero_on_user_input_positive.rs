// Positive: divides by a user-provided param with no zero-guard.

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct GasCalc;

#[contractimpl]
impl GasCalc {
    // BUG 1: gas_price is a user param, used as divisor, no `> 0` check.
    pub fn calc_cost(env: Env, fee: u128, gas_price: u128) -> u128 {
        fee / gas_price
    }

    // BUG 2: % variant — modulo by zero also panics.
    pub fn slot(env: Env, tx_id: u64, num_slots: u64) -> u64 {
        tx_id % num_slots
    }
}
