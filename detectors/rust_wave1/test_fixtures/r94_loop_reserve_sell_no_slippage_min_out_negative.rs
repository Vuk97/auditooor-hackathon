use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeFlash;
#[contractimpl]
impl SafeFlash {
    // OK: min_amount_out passed to router.swap
    pub fn sell_reserve(amount: u128, min_amount_out: u128) -> u128 {
        let _min = min_amount_out;
        router.swap_with_min(SwapArgs { amount_in: amount, amount_out_minimum: min_amount_out });
        0
    }
}
pub struct SwapArgs { pub amount_in: u128, pub amount_out_minimum: u128 }
struct Router;
impl Router { fn swap_with_min(&self, _a: SwapArgs) {} }
#[allow(non_upper_case_globals)]
static router: Router = Router;
