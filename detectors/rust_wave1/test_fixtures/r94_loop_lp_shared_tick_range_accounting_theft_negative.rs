use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePair;
#[contractimpl]
impl SafePair {
    // OK: looks up pair_liquidity_at(pair_id, tick_lower, tick_upper) first
    pub fn reallocate(pair_id: u64, tick_lower: i32, tick_upper: i32) {
        let liq = pair_liquidity_at(pair_id, tick_lower, tick_upper);
        pool.burn(tick_lower, tick_upper, liq);
    }
}
fn pair_liquidity_at(_p: u64, _l: i32, _u: i32) -> u128 { 0 }
struct Pool;
impl Pool { fn burn(&self, _l: i32, _u: i32, _liq: u128) {} }
#[allow(non_upper_case_globals)]
static pool: Pool = Pool;
