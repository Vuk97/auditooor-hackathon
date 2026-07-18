use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Shop;
#[contractimpl]
impl Shop {
    // BUG: uses AMM router.getAmountsIn as payment oracle
    pub fn buy(amount_out: u128) -> u128 {
        let amounts = router.get_amounts_in(amount_out);
        amounts
    }
}
struct Router;
impl Router { fn get_amounts_in(&self, _a: u128) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static router: Router = Router;
