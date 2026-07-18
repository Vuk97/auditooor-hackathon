use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;
type Address = [u8; 20];
pub struct Params { salt: [u8; 32] }
fn get_last_block_for(_salt: &[u8; 32]) -> u64 { 0 }
fn apply_penalty(_amt: u64) {}
fn current_block() -> u64 { 100 }
#[contract]
pub struct LiquidityPenaltyHook;
#[contractimpl]
impl LiquidityPenaltyHook {
    // BUG: penalty key is salt alone — attacker splits into many salts
    pub fn before_remove_liquidity(owner: Address, params: Params, amount: u64) {
        let last_block = get_last_block_for(&params.salt);
        if current_block() - last_block < 32 {
            apply_penalty(amount);
        }
    }
}
