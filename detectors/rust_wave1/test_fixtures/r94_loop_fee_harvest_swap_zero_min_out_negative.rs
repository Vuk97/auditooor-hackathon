use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeStrategy;
#[contractimpl]
impl SafeStrategy {
    // OK: computes min_out from oracle and passes it
    pub fn charge_fee(token_in: u64, amount_in: u128, expected_out: u128) -> u128 {
        let min_out = expected_out * 99 / 100;
        router.swap(SwapParams { token_in, amount_in, amount_out_minimum: min_out });
        0
    }
}
pub struct SwapParams { pub token_in: u64, pub amount_in: u128, pub amount_out_minimum: u128 }
struct Router;
impl Router { fn swap(&self, _p: SwapParams) {} }
#[allow(non_upper_case_globals)]
static router: Router = Router;
