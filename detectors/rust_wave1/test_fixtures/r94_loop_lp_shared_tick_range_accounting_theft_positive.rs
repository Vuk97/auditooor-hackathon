use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pair;
#[contractimpl]
impl Pair {
    // BUG: burns pool liquidity at tick range with no pair/owner key
    pub fn reallocate(tick_lower: i32, tick_upper: i32, liquidity: u128) {
        pool.burn(tick_lower, tick_upper, liquidity);
    }
}
struct Pool;
impl Pool { fn burn(&self, _l: i32, _u: i32, _liq: u128) {} }
#[allow(non_upper_case_globals)]
static pool: Pool = Pool;
