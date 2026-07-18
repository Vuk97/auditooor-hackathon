use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Strategy;
#[contractimpl]
impl Strategy {
    // BUG: swap with amount_out_minimum=0 in fee harvest path
    pub fn charge_fee(token_in: u64, amount_in: u128) -> u128 {
        router.swap(SwapParams { token_in, amount_in, amount_out_minimum: 0 });
        0
    }
}
pub struct SwapParams { pub token_in: u64, pub amount_in: u128, pub amount_out_minimum: u128 }
struct Router;
impl Router { fn swap(&self, _p: SwapParams) {} }
#[allow(non_upper_case_globals)]
static router: Router = Router;
