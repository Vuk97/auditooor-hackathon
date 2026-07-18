// Negative: refund updates the snapshot field after use.

use soroban_sdk::{contract, contractimpl, Env, Address};

const PRECISION: u128 = 1_000_000_000;

#[contract]
pub struct SafeBundler;

#[contractimpl]
impl SafeBundler {
    pub fn refund_deposit(env: Env, user: Address, user_pending: u128) {
        let last_total_shares_minted: u128 = Self::get_last_total(&env);
        let shares_to_revert = user_pending * last_total_shares_minted / PRECISION;
        Self::credit_shares(&env, user, shares_to_revert);
        // FIX: decrement the snapshot after the refund
        Self::set_last_total(&env, last_total_shares_minted - shares_to_revert);
    }

    pub fn refund_deposit_v2(env: Env, user: Address, user_pending: u128) {
        let mut last_total_shares_minted: u128 = Self::get_last_total(&env);
        let shares_to_revert = user_pending * last_total_shares_minted / PRECISION;
        Self::credit_shares(&env, user, shares_to_revert);
        last_total_shares_minted -= shares_to_revert;
        Self::set_last_total(&env, last_total_shares_minted);
    }

    fn get_last_total(_env: &Env) -> u128 { 0 }
    fn credit_shares(_env: &Env, _user: Address, _amt: u128) {}
    fn set_last_total(_env: &Env, _v: u128) {}
}
