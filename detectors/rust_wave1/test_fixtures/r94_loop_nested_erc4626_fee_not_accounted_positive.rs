use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Wrapper;
#[contractimpl]
impl Wrapper {
    // BUG: calls underlying.preview_deposit but doesn't account for fee
    pub fn deposit(assets: u128) -> u128 {
        let shares = underlying.preview_deposit(assets);
        shares
    }
}
struct Underlying;
impl Underlying { fn preview_deposit(&self, _a: u128) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static underlying: Underlying = Underlying;
