use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Flash;
#[contractimpl]
impl Flash {
    // BUG: sells reserve via swap, no min_out arg
    pub fn sell_reserve(amount: u128) -> u128 {
        router.swap(amount);
        0
    }
}
struct Router;
impl Router { fn swap(&self, _a: u128) {} }
#[allow(non_upper_case_globals)]
static router: Router = Router;
