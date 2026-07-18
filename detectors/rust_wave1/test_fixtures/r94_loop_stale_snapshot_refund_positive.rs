// Positive: refund reads last_total_shares_minted, uses it in share math,
// never decrements. Based on Solodit #61618 (Neutral Trade).

use soroban_sdk::{contract, contractimpl, Env, Address};

const PRECISION: u128 = 1_000_000_000;

#[contract]
pub struct Bundler;

#[contractimpl]
impl Bundler {
    pub fn refund_deposit(env: Env, user: Address, user_pending: u128) {
        // Read the stale snapshot
        let last_total_shares_minted: u128 = Self::get_last_total(&env);
        // Share math using the snapshot
        let shares_to_revert = user_pending * last_total_shares_minted / PRECISION;
        // Transfer/credit shares back
        Self::credit_shares(&env, user, shares_to_revert);
        // BUG: never updates last_total_shares_minted; next refund over-pays.
    }

    fn get_last_total(_env: &Env) -> u128 { 0 }
    fn credit_shares(_env: &Env, _user: Address, _amt: u128) {}
}
